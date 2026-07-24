use std::{
    collections::VecDeque,
    net::SocketAddr,
    ops::Deref,
    task::{Context, Poll, Waker},
};

use crate::{
    ice2::{
        candidate::{CandidatePair, FoundationPair, LocalCandidate, RemoteCandidate},
        check::{
            ConnectivityCheckResult, IncomingConnectivityCheckResponse, OutgoingConnectivityCheck,
            OutgoingConnectivityCheckHandle,
        },
    },
    AgentRole,
};

/// Redundant candidate error.
#[derive(Debug, Clone, Copy)]
pub struct RedundantCandidate;

/// ICE checklist as defined in RFC 8445.
pub struct Checklist {
    agent_role: AgentRole,
    tie_breaker: u64,
    local_candidates: Vec<LocalCandidate>,
    remote_candidates: Vec<RemoteCandidate>,
    no_more_local_candidates: bool,
    no_more_remote_candidates: bool,
    pairs: Vec<ChecklistEntry>,
    aux: Vec<ChecklistEntry>,
    triggered: VecDeque<TriggeredCheck>,
    valid: Vec<ValidPair>,
    check_consumer: Option<Waker>,
    next_check_id: u64,
    scheduling: bool,
    done: bool,
}

impl Checklist {
    /// Create a new checklist.
    pub fn new(agent_role: AgentRole, tie_breaker: u64) -> Self {
        Self {
            agent_role,
            tie_breaker,
            local_candidates: Vec::new(),
            remote_candidates: Vec::new(),
            no_more_local_candidates: false,
            no_more_remote_candidates: false,
            pairs: Vec::new(),
            aux: Vec::new(),
            triggered: VecDeque::new(),
            valid: Vec::new(),
            check_consumer: None,
            next_check_id: 0,
            scheduling: false,
            done: true,
        }
    }

    /// Add a given local candidate.
    pub fn add_local_candidate(
        &mut self,
        candidate: Option<LocalCandidate>,
    ) -> Result<(), RedundantCandidate> {
        if let Some(new) = candidate {
            debug_assert!(!self.no_more_local_candidates);

            let old = self.local_candidates.iter_mut().find(|c| {
                c.component() == new.component() && c.base() == new.base() && c.addr() == new.addr()
            });

            if let Some(old) = old {
                if new.priority() > old.priority() {
                    *old = new.clone();
                } else {
                    return Err(RedundantCandidate);
                }
            } else {
                self.local_candidates.push(new.clone());
            }

            for index in 0..self.remote_candidates.len() {
                // we cannot iterate directly over the candidates because we
                // need to borrow self in every iteration
                let remote = &self.remote_candidates[index];

                if let Ok(pair) = CandidatePair::new(new.clone(), remote.clone()) {
                    self.add_candidate_pair(pair, false);
                }
            }

            self.prune_candidate_pairs();
        } else {
            self.no_more_local_candidates = true;
        }

        if let Some(task) = self.check_consumer.take() {
            task.wake();
        }

        Ok(())
    }

    /// Add a given remote candidate.
    pub fn add_remote_candidate(&mut self, candidate: Option<RemoteCandidate>) {
        if let Some(new) = candidate {
            debug_assert!(!self.no_more_remote_candidates);

            let old = self
                .remote_candidates
                .iter_mut()
                .find(|c| c.component() == new.component() && c.addr() == new.addr());

            if let Some(old) = old {
                if new.priority() > old.priority() {
                    *old = new.clone();
                } else {
                    return;
                }
            } else {
                self.remote_candidates.push(new.clone());
            }

            for index in 0..self.local_candidates.len() {
                // we cannot iterate directly over the candidate because we need to
                // borrow self in every iteration
                let local = &self.local_candidates[index];

                if let Ok(pair) = CandidatePair::new(local.clone(), new.clone()) {
                    self.add_candidate_pair(pair, false);
                }
            }

            self.prune_candidate_pairs();
        } else {
            self.no_more_remote_candidates = true;
        }

        if let Some(task) = self.check_consumer.take() {
            task.wake();
        }
    }

    /// Get the number of candidate pairs in the checklist.
    pub fn len(&self) -> usize {
        self.pairs.len()
    }

    /// Clear all failed candidate pairs from the checklist.
    pub fn clear_failed(&mut self) {
        self.pairs.retain(|e| !e.is_failed());
    }

    /// Truncate the checklist to a given length.
    pub fn truncate(&mut self, len: usize) {
        self.pairs.truncate(len);

        if let Some(task) = self.check_consumer.take() {
            task.wake();
        }
    }

    /// Get an iterator over foundations of frozen candidate pairs.
    pub fn frozen_pair_foundations(&self) -> impl Iterator<Item = &FoundationPair> {
        self.pairs
            .iter()
            .filter(|e| e.is_frozen())
            .map(|e| e.foundation())
    }

    /// Check if there is a pending candidate pair with a given foundation.
    ///
    /// A pending candidate pair is a pair that is either in the "waiting" or
    /// "in-progress" state.
    pub fn is_pending_foundation(&self, foundation: &FoundationPair) -> bool {
        self.pairs
            .iter()
            .filter(|e| e.is_pending())
            .any(|e| e.foundation() == foundation)
    }

    /// Poll the next connectivity check to be performed.
    pub fn poll_next_check(
        &mut self,
        cx: &mut Context<'_>,
        unfreeze: Option<&FoundationPair>,
    ) -> Poll<Option<OutgoingConnectivityCheck>> {
        if self.done {
            return Poll::Ready(None);
        }

        let mut index = None;

        // take the first triggered check (if any)
        while index.is_none() {
            if let Some(triggered) = self.triggered.pop_front() {
                index = self.find_candidate_pair_position(|e| {
                    let local = e.local_candidate();
                    let remote = e.remote_candidate();

                    (e.is_frozen() || e.is_waiting())
                        && local.base() == triggered.local_base
                        && remote.addr() == triggered.remote_addr
                });
            } else {
                break;
            }
        }

        // if there are no triggered checks, take the first waiting entry
        if index.is_none() {
            index = self.find_candidate_pair_position(|e| e.is_waiting());
        }

        // if there are no waiting entries, unfreeze the first entry with a
        // given foundation
        if index.is_none() {
            if let Some(foundation) = unfreeze {
                index = self
                    .pairs
                    .iter_mut()
                    .enumerate()
                    .filter(|(_, e)| e.is_frozen())
                    .find(|(_, e)| e.foundation() == foundation)
                    .map(|(i, e)| {
                        e.unfreeze();

                        i
                    });
            }
        }

        // if all checks are done, we're a controlling agent and there are
        // valid pair that should be nominated, nominate them

        // TODO: If we're a controlling agent and all checks have been
        //   performed, nominate a valid pair with the highest priority.

        if let Some(entry) = index.map(|idx| &mut self.pairs[idx]) {
            let id = self.next_check_id;

            self.next_check_id = self.next_check_id.wrapping_add(1);

            Poll::Ready(Some(entry.start(id, self.agent_role, self.tie_breaker)))
        } else {
            let task = cx.waker();

            self.check_consumer = Some(task.clone());

            Poll::Pending
        }
    }

    /// Process a given connectivity check response.
    pub fn process_check_response(
        &mut self,
        response: IncomingConnectivityCheckResponse,
    ) -> Option<FoundationPair> {
        let id = response.id();
        let result = response.result();

        let Some(entry) = self.find_candidate_pair_mut(|e| e.check_id() == Some(id)) else {
            return None;
        };

        entry.process_check_result(result);

        let pair = entry.pair.clone();

        let foundation = pair.foundation();
        let local = pair.local();
        let remote = pair.remote();
        let nominated = entry.is_nominated();
        let base = local.base();

        if result == ConnectivityCheckResult::RoleConflict {
            self.trigger_check(base, remote.addr());
        } else if let ConnectivityCheckResult::Success(reflexive_addr) = result {
            let data_stream = local.data_stream();
            let component = local.component();

            let mut local = local.clone();

            if local.addr() != reflexive_addr {
                local =
                    LocalCandidate::peer_reflexive(data_stream, component, base, reflexive_addr);
            }

            if let Ok(pair) = CandidatePair::new(local, remote.clone()) {
                self.add_valid_pair(pair, nominated);
            }
        } else if result == ConnectivityCheckResult::Failed && nominated {
            // TODO: remove the pair from the valid list and set the checklist state to failed
        }

        if let Some(task) = self.check_consumer.take() {
            task.wake();
        }

        Some(foundation.clone())
    }

    /// Unfreeze all candidate pairs with a given foundation.
    pub fn unfreeze_foundation(&mut self, foundation: &FoundationPair) {
        self.pairs
            .iter_mut()
            .filter(|e| e.is_frozen() && e.foundation() == foundation)
            .for_each(|e| e.unfreeze());

        if let Some(task) = self.check_consumer.take() {
            task.wake();
        }
    }

    /// Get the best valid pair for a given component.
    pub fn get_best_valid_pair(&self, component: u8) -> Option<CandidatePair> {
        self.valid
            .iter()
            .filter(|pair| pair.component() == component)
            .max_by_key(|pair| pair.priority(self.agent_role))
            .map(|pair| pair.pair.clone())
    }

    /// Update the agent role used by this checklist.
    pub fn set_agent_role(&mut self, role: AgentRole, tie_breaker: u64) {
        if self.agent_role == role {
            return;
        }

        self.agent_role = role;
        self.tie_breaker = tie_breaker;

        // sort the checklist again if the agent role has changed
        self.sort_candidate_pairs();
    }

    /// Add a given candidate pair.
    fn add_candidate_pair(&mut self, pair: CandidatePair, nominated: bool) {
        let mut entry = ChecklistEntry::new(pair, nominated);

        // we can immediately switch the pair into the waiting state if there
        // is at least one successful check in the corresponding foundation
        // group
        let successful = self
            .pairs
            .iter()
            .filter(|e| e.foundation() == entry.foundation())
            .filter(|e| e.is_success())
            .count();

        if successful > 0 {
            entry.unfreeze();
        }

        self.pairs.push(entry);

        self.scheduling = true;
        self.done = false;
    }

    /// Sort the candidate pairs by their priority.
    fn sort_candidate_pairs(&mut self) {
        self.pairs.sort_unstable_by(|a, b| {
            let a = a.priority(self.agent_role);
            let b = b.priority(self.agent_role);

            b.cmp(&a)
        })
    }

    /// Prune the candidate pairs.
    fn prune_candidate_pairs(&mut self) {
        self.sort_candidate_pairs();

        let mut pairs = std::mem::take(&mut self.pairs);

        // put the auxiliary vector in place of `self.pairs` to avoid excessive
        // allocations (`self.aux` will be an empty `Vec` after this call)
        std::mem::swap(&mut self.pairs, &mut self.aux);

        self.pairs.clear();

        for pair in pairs.drain(..) {
            let local = pair.local_candidate();
            let remote = pair.remote_candidate();

            let prev = self.get_candidate_pair_mut(local.base(), remote.addr());

            if let Some(prev) = prev {
                prev.update(pair);
            } else {
                self.pairs.push(pair);
            }
        }

        // reuse the original vector as auxiliary
        self.aux = pairs;
    }

    /// Get a candidate pair having a given local base address and a given
    /// remote address.
    fn get_candidate_pair_mut(
        &mut self,
        local_base: SocketAddr,
        remote_addr: SocketAddr,
    ) -> Option<&mut ChecklistEntry> {
        self.find_candidate_pair_mut(|c| {
            let local = c.local_candidate();
            let remote = c.remote_candidate();

            local.base() == local_base && remote.addr() == remote_addr
        })
    }

    /// Find a candidate pair matching a given predicate.
    fn find_candidate_pair_mut<F>(&mut self, f: F) -> Option<&mut ChecklistEntry>
    where
        F: FnMut(&ChecklistEntry) -> bool,
    {
        self.find_candidate_pair_position(f)
            .map(|idx| &mut self.pairs[idx])
    }

    /// Find position of a candidate pair matching a given predicate.
    fn find_candidate_pair_position<F>(&self, f: F) -> Option<usize>
    where
        F: FnMut(&ChecklistEntry) -> bool,
    {
        self.pairs.iter().position(f)
    }

    /// Trigger check for a given candidate pair.
    ///
    /// The triggered check will be scheduled as soon as there is a free check
    /// slot.
    fn trigger_check(&mut self, local_base: SocketAddr, remote_addr: SocketAddr) {
        // NOTE: We need to reset the state of the corresponding check to
        // "waiting". See RFC 5245, section 7.2.1.4 for more details.
        if let Some(check) = self.get_candidate_pair_mut(local_base, remote_addr) {
            if !check.is_success() {
                check.trigger();
            }
        }

        self.triggered
            .push_back(TriggeredCheck::new(local_base, remote_addr));

        self.scheduling = true;
        self.done = false;
    }

    /// Cancel all checks for a given component.
    fn cancel_checks(&mut self, component: u8) {
        for check in &mut self.pairs {
            if check.component() == component {
                check.cancel();
            }
        }
    }

    /// Add a new valid pair.
    fn add_valid_pair(&mut self, pair: CandidatePair, nominated: bool) {
        let local = pair.local();
        let remote = pair.remote();
        let component = pair.component();

        let existing = self.valid.iter_mut().find(|pair| {
            let l = pair.local();
            let r = pair.remote();

            l.addr() == local.addr() && r.addr() == remote.addr()
        });

        if let Some(valid) = existing {
            if pair.priority(self.agent_role) > valid.priority(self.agent_role) {
                valid.pair = pair;
            }

            valid.nominated |= nominated;
        } else {
            self.valid.push(ValidPair::new(pair, nominated));
        }

        if nominated {
            self.cancel_checks(component);
        }
    }

    /// Get nominated pair for a given component ID.
    fn get_nominated_pair(&self, component: u8) -> Option<&CandidatePair> {
        self.valid
            .iter()
            .find(|pair| pair.component() == component && pair.nominated)
            .map(|pair| &pair.pair)
    }
}

/// Triggered check identifier.
struct TriggeredCheck {
    local_base: SocketAddr,
    remote_addr: SocketAddr,
}

impl TriggeredCheck {
    /// Create a new triggered check ID.
    fn new(local_base: SocketAddr, remote_addr: SocketAddr) -> Self {
        Self {
            local_base,
            remote_addr,
        }
    }
}

/// Valid candidate pair.
struct ValidPair {
    pair: CandidatePair,
    nominated: bool,
}

impl ValidPair {
    /// Create a new valid candidate pair.
    fn new(pair: CandidatePair, nominated: bool) -> Self {
        Self { pair, nominated }
    }
}

impl Deref for ValidPair {
    type Target = CandidatePair;

    fn deref(&self) -> &Self::Target {
        &self.pair
    }
}

/// Checklist entry containing a candidate pair and its current state.
struct ChecklistEntry {
    pair: CandidatePair,
    state: CheckState,
    nominated: bool,
}

impl ChecklistEntry {
    /// Create a new checklist entry.
    fn new(pair: CandidatePair, nominated: bool) -> Self {
        Self {
            pair,
            state: CheckState::Frozen,
            nominated,
        }
    }

    /// Get the component ID.
    fn component(&self) -> u8 {
        self.pair.component()
    }

    /// Get the priority of the candidate pair.
    fn priority(&self, local_role: AgentRole) -> u64 {
        self.pair.priority(local_role)
    }

    /// Get the local candidate.
    fn local_candidate(&self) -> &LocalCandidate {
        self.pair.local()
    }

    /// Get the remote candidate.
    fn remote_candidate(&self) -> &RemoteCandidate {
        self.pair.remote()
    }

    /// Get the foundation of the candidate pair.
    fn foundation(&self) -> &FoundationPair {
        self.pair.foundation()
    }

    /// Get the ID of the connectivity check if it is in progress.
    fn check_id(&self) -> Option<u64> {
        if let CheckState::InProgress(handle) = &self.state {
            Some(handle.id())
        } else {
            None
        }
    }

    /// Check if the current state is "frozen".
    fn is_frozen(&self) -> bool {
        matches!(self.state, CheckState::Frozen)
    }

    /// Check if the current state is "waiting".
    fn is_waiting(&self) -> bool {
        matches!(self.state, CheckState::Waiting)
    }

    /// Check if the current state is "waiting" or "in-progress".
    fn is_pending(&self) -> bool {
        matches!(self.state, CheckState::Waiting | CheckState::InProgress(_))
    }

    /// Check if the current state is "success".
    fn is_success(&self) -> bool {
        matches!(self.state, CheckState::Succeeded)
    }

    /// Check if the current state is "failed".
    fn is_failed(&self) -> bool {
        matches!(self.state, CheckState::Failed)
    }

    /// Check if the current state is "success", "failed" or "cancelled".
    fn is_done(&self) -> bool {
        matches!(
            self.state,
            CheckState::Succeeded | CheckState::Cancelled | CheckState::Failed
        )
    }

    /// Check if the candidate pair is nominated.
    fn is_nominated(&self) -> bool {
        self.nominated
    }

    /// Unfreeze the entry.
    ///
    /// The entry must be in the "frozen" state.
    fn unfreeze(&mut self) {
        debug_assert!(self.is_frozen());

        self.state = CheckState::Waiting;
    }

    /// Trigger the check.
    ///
    /// Regardless of the current state, the check will be switched to the
    /// "waiting" state.
    fn trigger(&mut self) {
        self.state = CheckState::Waiting;
    }

    /// Start a connectivity check.
    fn start(
        &mut self,
        id: u64,
        agent_role: AgentRole,
        tie_breaker: u64,
    ) -> OutgoingConnectivityCheck {
        debug_assert!(matches!(
            self.state,
            CheckState::Frozen | CheckState::Waiting
        ));

        let local = self.pair.local();
        let remote = self.pair.remote();

        let (check, handle) = OutgoingConnectivityCheck::new(
            id,
            agent_role,
            tie_breaker,
            local.clone(),
            remote.clone(),
            self.nominated,
        );

        self.state = CheckState::InProgress(handle);

        check
    }

    /// Process a given connectivity check result.
    fn process_check_result(&mut self, result: ConnectivityCheckResult) {
        self.state = match result {
            ConnectivityCheckResult::Success(_) => CheckState::Succeeded,
            ConnectivityCheckResult::RoleConflict => CheckState::Waiting,
            ConnectivityCheckResult::Failed => CheckState::Failed,
            ConnectivityCheckResult::Aborted => CheckState::Cancelled,
        };
    }

    /// Cancel the check.
    ///
    /// Unless the check is done, it will be switched to the "cancelled" state.
    fn cancel(&mut self) {
        if self.is_done() {
            return;
        }

        self.state = CheckState::Cancelled;
    }

    /// Update the current check pushing the state machine forward if possible.
    fn update(&mut self, other: ChecklistEntry) {
        if !self.nominated && other.nominated {
            *self = other;
        } else if self.nominated == other.nominated {
            match (&self.state, &other.state) {
                (CheckState::Frozen, _) => *self = other,
                (CheckState::Waiting, CheckState::InProgress(_)) => *self = other,
                (_, CheckState::Succeeded) => *self = other,
                (_, CheckState::Failed) => *self = other,
                (_, CheckState::Cancelled) => *self = other,
                _ => (),
            }
        }
    }
}

/// Connectivity check state.
enum CheckState {
    Frozen,
    Waiting,
    InProgress(OutgoingConnectivityCheckHandle),
    Succeeded,
    Failed,
    Cancelled,
}
