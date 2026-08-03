# Agentic Response CRW26 Paper Outline Notes

This note summarizes the structure of the previous paper,
`paper/autonomouscyber26.tex`, and how to adapt that logic for the new
`paper/agentic_response_crw26.tex` paper.

## 1. Abstract

The old paper's abstract follows this structure:

1. Problem: manual incident response is slow, while traditional
   decision-theoretic planning is often too abstract for operational systems.
2. Gap: LLM agents can generate executable actions, but are unreliable and
   prone to hallucination when used without principled planning.
3. Method: a rollout planner generates high-level tactical response strategies;
   an LLM agent translates them into executable commands; a digital twin
   supports simulation and emulation.
4. Result: the proposed method improves recovery time and recovery rate over
   frontier LLMs and prior baselines.

For the new paper, the abstract should shift the emphasis:

- The problem is not only recovery planning, but also whether the model can
  infer the attack sequence from system context and IDS alerts.
- The evaluation uses CSLE level9, which has a much more complex topology than
  the previous 5-server setup.
- The digital twin is used to expose whether predicted attacks and predicted
  recovery actions are operationally equivalent to the reference execution.

## 2. Introduction

The old paper's introduction has this flow:

1. Define incident response and explain why manual response is slow and
   expert-intensive.
2. Introduce autonomous cyber defense and decision-theoretic planning.
3. Explain that existing ACD methods often operate only at the tactical scale:
   they say which host to defend, but not how to execute recovery.
4. Introduce LLM agents as a way to generate operational commands.
5. Explain the weakness of prompt-only LLM agents: hallucination, unreliable
   planning, and limited planning horizon.
6. Propose multiscale planning: tactical rollout plus operational LLM command
   generation.
7. Introduce digital twins as simulation and emulation environments.
8. Summarize experiments on a 5-server topology and list contributions.

For the new paper, keep the same motivation structure, but replace the
experimental story:

- Old version: recovery planning on a 5-server toy topology.
- New version: incident and recovery evaluation on CSLE level9 with 30+
  containers, multiple subnets, vulnerable services, IDS sensors, and
  multi-homed hosts.

The new introduction should emphasize:

- The model first infers the incident and attack sequence from alerts.
- The predicted attack is executed in DT16.
- The reference attack is observed from CSLE15.
- Attack inference errors should surface as executable state differences, not
  only as text differences.
- Recovery actions can then be evaluated on both the predicted DT state and the
  reference attack state.

## 3. Related Work

The old paper has four related-work blocks:

1. Decision-theoretic incident response:
   MDPs, POMDPs, control, game theory, reinforcement learning, and abstract
   planning.
2. LLM-based incident response:
   prompt-based agents, LLM-RL hybrids, and LLM-generated response commands.
3. Cybersecurity digital twins:
   simulation, emulation, forensic testing, event management, and operational
   validation.
4. Novelty:
   combining tactical planning, operational LLM command generation, and digital
   twin verification.

For the new paper, preserve these categories but update the novelty:

- The new work uses digital twins not only to verify recovery commands, but also
  to validate LLM-inferred attack sequences.
- It compares a reference CSLE execution with a homologous digital-twin
  execution.
- It studies a complex level9 topology with 30+ containers and multi-homed
  hosts rather than a 5-server topology.

## 4. Preliminaries

The old paper uses this section to define:

1. Incident response planning.
2. The six response stages:
   containment, assessment, preservation, eviction, hardening, restoration.
3. A POMDP model for response under partial observability.
4. Observations such as logs and IDS alerts.
5. Costs as recovery execution time.

The new paper can keep most of this section.

The main addition should be:

- In level9, observations include sidecar IDS alerts, native Snort alerts, and
  host-level post-attack evidence.
- The defender sees alerts and system topology, but not the ground-truth attack
  sequence.

## 5. Formalizing the Incident Response Use Case

The old paper's mathematical core is:

- The system has `N` components.
- Each component has a global state:
  safe or compromised.
- Each component also has a local six-stage recovery state:
  containment, assessment, preservation, eviction, hardening, restoration.
- The defender maintains a belief over the hidden state.
- Actions have a tactical part and an operational part.
- Costs combine recovery execution time and delay cost.
- State dynamics couple global compromise state and local recovery progress.

For the new paper, this is the most important place to change the model.

In the old paper:

- A component is basically one server in a 5-server topology.

In the new paper:

- A component should be a logical CSLE host/container identity, not a single IP.
- A component may be multi-homed and have several IP interfaces.

Examples:

- Samba host:
  `16.9.2.3 / 16.9.4.3 / 16.9.253.3`
- SSH host:
  `16.9.2.78 / 16.9.3.78 / 16.9.253.78`
- DVWA host:
  `16.9.4.74 / 16.9.5.74 / 16.9.253.74`
- Elasticsearch host:
  `16.9.5.62 / 16.9.6.62 / 16.9.7.62 / 16.9.253.62`

The new paper should explicitly state:

```text
A component is a logical container/host identity, possibly with multiple IP
interfaces. Compromise is evaluated at the host identity level, while IDS alerts
and network flows are observed at the interface/IP level.
```

## 6. Agentic Multiscale Response Planning

The old method has three main parts:

1. Offline fine-tuning:
   incident assessment, belief/state generation, and response action generation.
2. Digital twin:
   simulation for tactical planning and emulation for operational command
   verification.
3. Tactical and operational planning:
   tactical rollout selects which component to recover; operational rollout
   selects the local recovery action and verifies commands in the digital twin.

The new paper should add one earlier stage:

```text
Incident/attack inference:
System + Alerts -> Incident Summary -> Core Attack Actions -> Adapter ->
Executable CSLE Action Sequence -> DT Execution -> Post-Attack State Comparison
```

The new method section can be organized as:

1. Incident inference from alerts.
2. Core attack reconstruction.
3. Adapter from core attack actions to CSLE runtime actions.
4. DT attack execution and equivalence checking.
5. Recovery rollout planning.
6. Command-agent execution and verification.
7. Cross-environment comparison between CSLE15 and DT16.

## 7. Experiment

The old experiment section contains:

1. Experiment setup:
   model checkpoint, LoRA fine-tuning, datasets, digital twin topology, attack
   scenarios.
2. LLM generation evaluation:
   incident tactic prediction, belief generation, and action generation.
3. Recovery-time evaluation:
   baselines, evaluation scenarios, recovery time, and recovery rate.
4. Discussion:
   performance explanation, limitations, and relationship to playbooks.

The new experiment section should be built around CSLE level9:

- Reference environment: CSLE execution 15.
- Digital twin environment: CSLE execution 16.
- Topology: 30+ containers, many subnets, multiple vulnerable services,
  honeypots/decoys, router IDS, sidecar IDS, and management network.
- Attacks: experienced, expert, and novice attack traces.
- Inputs: system description and sidecar IDS alerts.
- Outputs: incident summaries, tactics, techniques, core attack predictions,
  post-attack state, recovery commands, and post-recovery observations.

Suggested research questions:

1. RQ1: Can checkpoint-850 infer incident details, tactics, and techniques from
   level9 alerts?
2. RQ2: Can it infer the core attack actions from the incident summary?
3. RQ3: Does executing the predicted attack in DT16 reproduce the reference
   CSLE15 post-attack state?
4. RQ4: Does recovery rollout generate actions that restore the attacked level9
   system?
5. RQ5: How does the move from a 5-server topology to a 30+ container level9
   topology change the failure modes?

## 8. Conclusion

The old conclusion says that multiscale planning plus digital-twin verification
improves agentic incident response.

The new conclusion should say:

- Executable digital twins are useful not only for validating recovery actions,
  but also for validating whether the model inferred the attack correctly.
- Text-level correctness is insufficient.
- A model may identify the main exploited services but still miss a local
  privilege escalation step that changes the final root state.
- Comparing DT16 and CSLE15 makes such errors observable.

## Suggested New Paper Structure

The new `agentic_response_crw26.tex` can follow this structure:

1. Introduction
2. Background and Related Work
3. Problem Formulation
4. CSLE Level9 Digital-Twin Testbed
5. LLM-Based Incident and Attack Inference
6. Executable Attack Reconstruction in DT16
7. Agentic Recovery Rollout
8. Experiments
9. Discussion and Limitations
10. Conclusion

## One-Sentence Difference

The old paper is about recovery planning on a 5-server digital twin.

The new paper is about using a complex CSLE level9 digital twin with 30+
containers to validate both LLM-inferred attack sequences and LLM-guided recovery
actions.
