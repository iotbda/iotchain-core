# ICP (IOTChain Consensus Protocol)

The ICP subsystem is an abstract implementation of ICP, a protocol for federated
byzantine agreement, intended to drive a distributed system built around the
"replicated state machine" formalism. ICP is defined without reference to any
particular interpretation of the concepts of "slot" or "value", nor any
particular network communication system or replicated state machine.

This separation from the rest of the system is intended to make the
implementation of ICP easier to model, compare to the paper describing the
protocol, audit for correctness, and extract for reuse in different programs at
a later date.

The [ICPDriver class](ICPDriver.h) should be subclassed by any module wishing to
implement consensus using the ICP protocol, implementing the necessary abstract
methods for handling ICP-generated events, and calling methods from the central
[ICP base-class](ICP.h) methods to receive incoming messages.
The messages making up the protocol are defined in XDR,
in the file [IOTChain-ICP.x](../xdr/IOTChain-ICP.x)

The `iotchain-core` program has a single subclass of ICPDriver called
[Herder](../herder), which gives a specific interpretation to "slot" and
"value", and connects ICP up with a specific broadcast communication medium
([Overlay](../overlay)) and specific replicated state machine
([LedgerManager](../ledger)).

For details of the protocol itself, see the [paper on ICP](https://iotbdalliance.com/papers/iotchain-consensus-protocol.pdf).
