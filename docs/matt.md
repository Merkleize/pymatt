MATT is an acronym for _Merkleize All The Things_, and is a research project for an approach to bitcoin smart contracts that only require relatively minimal changes to bitcoin's Script, while allowing very general constructions.

This page introduces the general idea of the framework.


### Key concept: Covenants

In Bitcoin, coins are locked in UTXOs (short for Unspent Transaction Outputs). A UTXO contains the Script that specifies the conditions to spend those coins ("Alice can spend", or "Alice can spend, or Bob can spend after a month", etc.).

Today, there is no way in Bitcoin to add constraints on where coins can be spent, if the conditions in the Script are satisfied.

A script that adds such restriction is called a covenant, and that is not possible in Bitcoin today, at least not within the Script language. Adding the capability to do so in Script is an increasingly active area of research.

## The covenant introduced in MATT
The core idea in MATT is to introduce the following capability to be accessible within Script:

- force an output to have a certain Script (and their amounts)
- optionally, attach a piece of data to an output
- read the data of the current input (or another one)

The first is common to many other covenant proposals, for example [OP_CHECKTEMPLATEVERIFY](https://github.com/bitcoin/bips/blob/master/bip-0119.mediawiki) is a long-discussed proposal that can constrain all the outputs at the same time.

The part relative to the data is more specific: this data can be an arbitrary buffer. The key is that the data of an output is not decided when the UTXO is first created, but it is dynamically computed in Script (and therefore it can depend on "parameters" that are passed by the spender). This is extremely powerful, as it allows to create some sort of "state machines" where the execution can decide:

- what is the next "state" of the state machine (by constraining the Script of the outputs)
- what is the "data" attached to the next state

There are many ways to introduce these capabilities in bitcoin Script. This repository is based on the [OP_CHECKCONTRACTVERIFY](./checkcontractverify.md) opcode, which is tailored specifically to smart contract using the ideas of MATT; it would be easy to port the code of the examples in this repository to other approaches.

## Merkleize All The Things

The rest of this page goes into more details into what the framework

### (1) Merkleizing the data
Here we come to the second core idea: if we can only attach a single piece of data (32 bytes), how can we execute more complex "contracts" that require accessing/storing more data?

The solution is to use the 32-byte data as a commitment to a larger collection containing all the required data of the contract. This can be done with [Merkle trees](https://en.wikipedia.org/wiki/Merkle_tree), which are not currently possible in Script, but become possible by adding a simple opcode like `OP_CAT`, that takes two stack elements and concatenates them.

It is not difficult to convince oneself that the capabilities of the covenant described above, together with the ability to compress arbitrary data in a single hash, allows chains of transactions to be programmed to perform arbitrary computation. More on this below.

### (2) Merkleizing the Script
The concept of this section is not really anything new in MATT, as it was introduced in the Taproot soft fork, which is active in bitcoin since November 2021.

When you represent a contract as a Finite State Machine, you often have situations where a certain state can transition to multiple other states of the FSM.

For example, if the smart contract is encoding a game of Tic-Tac-Toe between Alice and Bob, and it's Alice's turn, one transition encodes "Alice plays her move". However, Alice might stop playing, so you likely want to allow Bob to automatically win the game if Alice doesn't play her move within 1 day. So a second "state transition" in the node that represents Alice's turn could be "After 1 day, Bob can take the money".

More complicated contracts can have many possible transitions from the same node, and taproot makes it possible by using - you guessed it - a Merkle tree of all the possible transition. Each leaf of this Merkle tree contains a bitcoin Script, as usual.

### (3) Merkleizing the Execution
This section describes some more advanced applications of the ideas described above; unavoidably, this section will be the hardest to read.

What we said above is already enough to represent some very interesting smart contracts, like [vaults](../examples/vault/), [Rock-Paper-Scissors](../examples/rps), and a lot more.

However, there are smart contracts that are way too expensive to execute in the way described above, simply because bitcoin Script is not powerful enough to perform complex computations (this is by design, as it helps to keep the validation efficient and cheap, which is crucial for people to be able to run bitcoin full nodes!).

Sure, one could decompose the computation in a chain of hundreds, or thousands of little state-machine updates − but this certainly does not scale!

MATT allows an interesting solution to this problem, by using an idea known as ___fraud proofs___.

It goes like this: suppose that a transition from a certain state to another state is only allowed if Alice produces an input x that satisfies a certain complicated condition. For example, _x_ must be a prime number. Script does not have any opcode to check if a number is prime!

Therefore, we modify the contract as follows:

- Alice posts the number _x_ (unconditionally), and the contract moves to a "Challenge phase"
- During the challenge phase, if Bob verifies that _x_ is not prime, Bob can challenge the assertion.
- Otherwise, after some time (say, 1 day), Alice can continue as normal: she produced an _x_ that Bob did not challenge, so it is probably a prime!

What happens if Bob does start a challenge? In that case, the contract enters a different stage: a fraud proof protocol. The protocol involves multiple transaction from both parties, but it guarantees the following: if Alice was lying, she will be exposed and lose her money; vice-versa, if she wasn't lying, Bob will lose his money. Lying is not profitable!

The execution of the fraud proof protocol requires yet another Merkle tree, this time built off-chain by the participants while they execute the computation. See [fraud.py](../matt/hub/fraud.py) for a detailed description and implementation of the fraud proof protocol.