use std::{
    collections::VecDeque,
    net::SocketAddr,
    ops::Deref,
    task::{Context, Poll, Waker},
};

use crate::{
    ice2::{
        candidate::{
            CandidateKind, CandidatePair, FoundationPair, LocalCandidate, RemoteCandidate,
        },
        check::{
            ConnectivityCheckResult, IncomingConnectivityCheckRequest,
            IncomingConnectivityCheckResponse, OutgoingConnectivityCheck,
            OutgoingConnectivityCheckHandle,
        },
    },
    AgentRole,
};

/// Redundant candidate error.
#[derive(Copy, Clone)]
pub struct RedundantCandidate(());

/// Checklist state.
#[derive(Copy, Clone, PartialEq, Eq, Hash)]
pub enum ChecklistState {
    Running,
    Failed,
    Success,
}

/// ICE checklist as defined in RFC 8445.
pub struct Checklist {
    agent_role: AgentRole,
    tie_breaker: u64,
    local_candidates: Vec<LocalCandidate>,
    remote_candidates: Vec<RemoteCandidate>,
    no_more_local_candidates: bool,
    no_more_remote_candidates: bool,
    entries: Vec<ChecklistEntry>,
    aux: Vec<ChecklistEntry>,
    triggered: VecDeque<TriggeredCheck>,
    valid: Vec<ValidPair>,
    check_consumer: Option<Waker>,
    next_check_id: u64,
    state: ChecklistState,
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
            entries: Vec::new(),
            aux: Vec::new(),
            triggered: VecDeque::new(),
            valid: Vec::new(),
            check_consumer: None,
            next_check_id: 0,
            state: ChecklistState::Running,
        }
    }

    /// Add a given local candidate.
    pub fn add_local_candidate(
        &mut self,
        candidate: LocalCandidate,
    ) -> Result<(), RedundantCandidate> {
        debug_assert!(!self.no_more_local_candidates);

        let new = candidate;

        let old = self.local_candidates.iter_mut().find(|c| {
            c.component() == new.component() && c.base() == new.base() && c.addr() == new.addr()
        });

        if let Some(old) = old {
            if new.priority() > old.priority() {
                *old = new.clone();
            } else {
                return Err(RedundantCandidate(()));
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

        self.prune();

        if let Some(task) = self.check_consumer.take() {
            task.wake();
        }

        Ok(())
    }

    /// Call this method when there are no more local candidates.
    pub fn no_more_local_candidates(&mut self) {
        self.no_more_local_candidates = true;

        if let Some(task) = self.check_consumer.take() {
            task.wake();
        }
    }

    /// Add a given remote candidate.
    pub fn add_remote_candidate(&mut self, candidate: RemoteCandidate) {
        let new = candidate;

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

        self.prune();

        if let Some(task) = self.check_consumer.take() {
            task.wake();
        }
    }

    /// Call this method when there are no more remote candidates.
    pub fn no_more_remote_candidates(&mut self) {
        self.no_more_remote_candidates = true;

        if let Some(task) = self.check_consumer.take() {
            task.wake();
        }
    }

    /// Get the number of candidate pairs in the checklist.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Clear all failed candidate pairs from the checklist.
    pub fn clear_failed(&mut self) {
        self.entries.retain(|e| !e.is_failed());

        if let Some(task) = self.check_consumer.take() {
            task.wake();
        }
    }

    /// Truncate the checklist to a given length.
    pub fn truncate(&mut self, len: usize) {
        self.entries.truncate(len);

        if let Some(task) = self.check_consumer.take() {
            task.wake();
        }
    }

    /// Get an iterator over foundations of frozen candidate pairs.
    pub fn frozen_pair_foundations(&self) -> impl Iterator<Item = &FoundationPair> {
        self.entries
            .iter()
            .filter(|e| e.is_frozen())
            .map(|e| e.foundation())
    }

    /// Check if there is a pending candidate pair with a given foundation.
    ///
    /// A pending candidate pair is a pair that is either in the "waiting" or
    /// "in-progress" state.
    pub fn is_pending_foundation(&self, foundation: &FoundationPair) -> bool {
        self.entries
            .iter()
            .filter(|e| e.foundation() == foundation)
            .any(|e| e.is_frozen() || e.is_waiting())
    }

    /// Take the next connectivity check to be performed.
    ///
    /// This method can be called before `poll_next_check` to generate the next
    /// connectivity check without unfreezing any foundation. The method will
    /// return the first triggered check or a check for first candidate pair in
    /// the "waiting" state  (if any).
    pub fn take_next_check(&mut self) -> Option<OutgoingConnectivityCheck> {
        if self.state != ChecklistState::Running {
            None
        } else if let Some(idx) = self.next_check_index(None) {
            Some(self.start_connectivity_check(idx))
        } else {
            None
        }
    }

    /// Poll the next connectivity check to be performed.
    pub fn poll_next_check(
        &mut self,
        cx: &mut Context<'_>,
        unfreeze: Option<&FoundationPair>,
    ) -> Poll<Option<OutgoingConnectivityCheck>> {
        if self.state != ChecklistState::Running {
            return Poll::Ready(None);
        } else if let Some(idx) = self.next_check_index(unfreeze) {
            return Poll::Ready(Some(self.start_connectivity_check(idx)));
        }

        // TODO: if all checks are done, we're a controlling agent and there
        //   are valid pairs that should be nominated, nominate them

        let task = cx.waker();

        self.check_consumer = Some(task.clone());

        Poll::Pending
    }

    /// Get index of an entry where the next connectivity check should be
    /// initiated.
    fn next_check_index(&mut self, unfreeze: Option<&FoundationPair>) -> Option<usize> {
        if self.state != ChecklistState::Running {
            return None;
        }

        // take the first triggered check (if any)
        while let Some(triggered) = self.triggered.pop_front() {
            let idx = self.find_entry_position(|e| {
                let local = e.local_candidate();
                let remote = e.remote_candidate();

                (e.is_frozen() || e.is_waiting())
                    && local.base() == triggered.local_base
                    && remote.addr() == triggered.remote_addr
            });

            if idx.is_some() {
                return idx;
            }
        }

        // if there are no triggered checks, take the first waiting entry
        if let Some(idx) = self.find_entry_position(|e| e.is_waiting()) {
            return Some(idx);
        }

        // if there are no waiting entries, unfreeze the first frozen entry
        // with a given foundation
        if let Some(foundation) = unfreeze {
            self.entries
                .iter_mut()
                .enumerate()
                .filter(|(_, e)| e.is_frozen())
                .find(|(_, e)| e.foundation() == foundation)
                .map(|(i, e)| {
                    e.unfreeze();

                    i
                })
        } else {
            None
        }
    }

    /// Start a connectivity check for a given entry.
    fn start_connectivity_check(&mut self, entry_idx: usize) -> OutgoingConnectivityCheck {
        let id = self.next_check_id;

        self.next_check_id = self.next_check_id.wrapping_add(1);

        let entry = &mut self.entries[entry_idx];

        entry.start(id, self.agent_role, self.tie_breaker)
    }

    /// Process a given connectivity check response.
    ///
    /// The method returns foundation of the candidate pair on successful
    /// connectivity check. The caller is responsible for unfreezing candidate
    /// pairs with the same foundation in all checklists.
    pub fn process_check_response(
        &mut self,
        response: IncomingConnectivityCheckResponse,
    ) -> Option<FoundationPair> {
        let id = response.id();
        let result = response.result();

        let Some(entry) = self.find_entry_mut(|e| e.check_id() == Some(id)) else {
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

            let local = self
                .local_candidates
                .iter()
                .find(|c| {
                    c.component() == component && c.base() == base && c.addr() == reflexive_addr
                })
                .cloned()
                .unwrap_or_else(|| {
                    LocalCandidate::peer_reflexive(data_stream, component, base, reflexive_addr)
                });

            if let Ok(pair) = CandidatePair::new(local, remote.clone()) {
                self.add_valid_pair(pair, nominated);
            }
        } else if result == ConnectivityCheckResult::Failed && nominated {
            self.remove_valid_pair(local.addr(), remote.addr());

            self.state = ChecklistState::Failed;
        }

        self.update_checklist_state();

        if let Some(task) = self.check_consumer.take() {
            task.wake();
        }

        if matches!(result, ConnectivityCheckResult::Success(_)) {
            Some(foundation.clone())
        } else {
            None
        }
    }

    /// Process a given incoming connectivity check request.
    pub fn process_check_request(&mut self, request: &IncomingConnectivityCheckRequest) {
        let data_stream = request.data_stream();
        let component = request.component();
        let base_addr = request.base_addr();
        let remote_addr = request.remote_addr();
        let remote_role = request.remote_role();

        let local_candidate = self
            .local_candidates
            .iter()
            .filter(|c| c.component() == component)
            .filter(|c| c.kind() != CandidateKind::ServerReflexive)
            .find(|c| c.base() == base_addr)
            .expect("unknown local candidate")
            .clone();

        let remote_candidate = self
            .remote_candidates
            .iter()
            .filter(|c| c.component() == component)
            .find(|c| c.addr() == remote_addr)
            .cloned()
            .unwrap_or_else(|| {
                RemoteCandidate::peer_reflexive(
                    data_stream,
                    component,
                    remote_addr,
                    request.priority(),
                )
            });

        let nominated = remote_role == AgentRole::Controlling && request.use_candidate();

        let Ok(pair) = CandidatePair::new(local_candidate, remote_candidate) else {
            return;
        };

        self.add_candidate_pair(pair, nominated);
        self.prune();

        let state = self
            .find_entry(|e| {
                let l = e.local_candidate();
                let r = e.remote_candidate();

                l.base() == base_addr && r.addr() == remote_addr
            })
            .map(|e| &e.state);

        if !matches!(state, Some(CheckState::Succeeded)) {
            self.trigger_check(base_addr, remote_addr);
        }
    }

    /// Unfreeze all candidate pairs with a given foundation.
    pub fn unfreeze_foundation(&mut self, foundation: &FoundationPair) {
        self.entries
            .iter_mut()
            .filter(|e| e.is_frozen() && e.foundation() == foundation)
            .for_each(|e| e.unfreeze());

        if let Some(task) = self.check_consumer.take() {
            task.wake();
        }
    }

    /// Get the best valid pair for a given component.
    pub fn get_best_valid_pair(&self, component: u8) -> Option<CandidatePair> {
        let nominated = self
            .valid
            .iter()
            .filter(|pair| pair.component() == component)
            .find(|pair| pair.nominated);

        if let Some(pair) = nominated {
            return Some(pair.pair.clone());
        }

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
        self.sort();
    }

    /// Add a given candidate pair.
    fn add_candidate_pair(&mut self, pair: CandidatePair, nominated: bool) {
        let mut entry = ChecklistEntry::new(pair, nominated);

        // we can immediately switch the pair into the waiting state if there
        // is at least one successful check in the corresponding foundation
        // group
        let successful = self
            .entries
            .iter()
            .filter(|e| e.foundation() == entry.foundation())
            .any(|e| e.is_success());

        if successful {
            entry.unfreeze();
        }

        self.entries.push(entry);
    }

    /// Sort the entries by the priority of their candidate pairs.
    fn sort(&mut self) {
        self.entries.sort_unstable_by(|a, b| {
            let a = a.priority(self.agent_role);
            let b = b.priority(self.agent_role);

            b.cmp(&a)
        })
    }

    /// Prune the checklist.
    fn prune(&mut self) {
        self.sort();

        let mut entries = std::mem::take(&mut self.entries);

        // put the auxiliary vector in place of `self.entries` to avoid
        // excessive allocations (`self.aux` will be an empty `Vec` after this
        // call)
        std::mem::swap(&mut self.entries, &mut self.aux);

        self.entries.clear();

        for entry in entries.drain(..) {
            let local = entry.local_candidate();
            let remote = entry.remote_candidate();

            let prev = self.find_entry_mut(|e| {
                let l = e.local_candidate();
                let r = e.remote_candidate();

                l.base() == local.base() && r.addr() == remote.addr()
            });

            if let Some(prev) = prev {
                prev.update(entry);
            } else {
                self.entries.push(entry);
            }
        }

        // reuse the original vector as auxiliary
        self.aux = entries;
    }

    /// Find an entry matching a given predicate.
    fn find_entry<F>(&self, f: F) -> Option<&ChecklistEntry>
    where
        F: FnMut(&ChecklistEntry) -> bool,
    {
        self.find_entry_position(f).map(|idx| &self.entries[idx])
    }

    /// Find an entry matching a given predicate.
    fn find_entry_mut<F>(&mut self, f: F) -> Option<&mut ChecklistEntry>
    where
        F: FnMut(&ChecklistEntry) -> bool,
    {
        self.find_entry_position(f)
            .map(|idx| &mut self.entries[idx])
    }

    /// Find position of an entry matching a given predicate.
    fn find_entry_position<F>(&self, f: F) -> Option<usize>
    where
        F: FnMut(&ChecklistEntry) -> bool,
    {
        self.entries.iter().position(f)
    }

    /// Trigger check for a given candidate pair.
    fn trigger_check(&mut self, local_base: SocketAddr, remote_addr: SocketAddr) {
        let Some(entry) = self.find_entry_mut(|e| {
            let local = e.local_candidate();
            let remote = e.remote_candidate();

            local.base() == local_base && remote.addr() == remote_addr
        }) else {
            return;
        };

        entry.trigger();

        self.triggered
            .push_back(TriggeredCheck::new(local_base, remote_addr));
    }

    /// Cancel all checks for a given component.
    fn cancel_checks(&mut self, component: u8) {
        for entry in &mut self.entries {
            if entry.component() == component {
                entry.cancel();
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

        // NOTE: This concludes ICE processing for the component.
        if nominated {
            self.cancel_checks(component);
        }
    }

    /// Remove a given valid pair.
    fn remove_valid_pair(&mut self, local_addr: SocketAddr, remote_addr: SocketAddr) {
        self.valid.retain(|pair| {
            let l = pair.local();
            let r = pair.remote();

            !(l.addr() == local_addr && r.addr() == remote_addr)
        });
    }

    /// Update the checklist state.
    fn update_checklist_state(&mut self) {
        if self.state != ChecklistState::Running
            || !self.no_more_local_candidates
            || !self.no_more_remote_candidates
        {
            return;
        }

        let all_checks_done = self.entries.iter().all(|e| e.is_done());

        if !all_checks_done {
            return;
        }

        let success = self
            .max_effective_component_id()
            .into_iter()
            .map(|max| 0..max)
            .flatten()
            .filter(|&component| self.has_component(component))
            .all(|component| self.has_valid_pair(component));

        if success {
            self.state = ChecklistState::Success;
        } else {
            self.state = ChecklistState::Failed;
        }
    }

    /// Get the maximum effective component ID.
    fn max_effective_component_id(&self) -> Option<u8> {
        let max_local_component_id = self.local_candidates.iter().map(|c| c.component()).max()?;
        let max_remote_component_id = self.remote_candidates.iter().map(|c| c.component()).max()?;

        Some(max_local_component_id.min(max_remote_component_id))
    }

    /// Check if a given component is being used.
    ///
    /// The component is considered being used if the checklist contains both
    /// local and remote candidates for the component.
    fn has_component(&self, component: u8) -> bool {
        let has_local_candidate = self
            .local_candidates
            .iter()
            .any(|c| c.component() == component);

        let has_remote_candidate = self
            .remote_candidates
            .iter()
            .any(|c| c.component() == component);

        has_local_candidate && has_remote_candidate
    }

    /// Check if there is at least one valid pair for a given component.
    fn has_valid_pair(&self, component: u8) -> bool {
        self.valid.iter().any(|pair| pair.component() == component)
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
        let nominated = self.nominated || other.nominated;

        match (&self.state, &other.state) {
            (CheckState::Frozen, _) => *self = other,
            (CheckState::Waiting, CheckState::InProgress(_)) => *self = other,
            (CheckState::Succeeded, _) => (),
            (_, CheckState::Succeeded) => *self = other,
            (CheckState::Failed, _) => (),
            (_, CheckState::Failed) => *self = other,
            (CheckState::Cancelled, _) => (),
            (_, CheckState::Cancelled) => *self = other,
            _ => (),
        }

        self.nominated = nominated;
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
