# Introduction

The content of this page is written with the current semantics of `OP_CHECKCONTRACTVERIFY` + `OP_CAT` in mind; however, it would equally apply to any implementation of the MATT framework.


## P2TR and _augmented_ P2TR

In a P2TR scriptPubKey, the output key is computed from an _internal pubkey_ `pk` and a `taptree`, as:

```
output_key = taproot_tweak(pk, taptree)
```

We call an _augmented_ P2TR any P2TR where the _internal pubkey_ is, in turn, computed from a _naked pubkey_ `naked_pk`, tweaked with some embedded `data`:

```
pk = tweak(naked_pk, data)
```

`OP_CHECKCONTRACTVERIFY` allows to verify that the `scriptPubkey` of an input or an output is a certain P2TR Script, possibly _augmented_ with some embedded data.

The embedded data is a 32-byte value.


## `OP_CHECKCONTRACTVERIFY`

This section describes the semantics of the `OP_CHECKCONTRACTVERIFY` opcode, as currently implemented in the [docker container for MATT](https://github.com/Merkleize/docker).

### Description

`OP_CHECKCONTRACTVERIFY` is only active for scripts spending a Segwit version 1 input.

Get `data`, `index`, `pk`, `taptree`, `flags` from the stack (bottom-to-top).

`OP_CHECKCONTRACTVERIFY` verifies that the scriptPubKey of the input/output with the given `index` is a P2TR script with a pubkey obtained by the x-only pubkey `pk`, optionally tweaked with `data`, optionally taptweaked with `taptree`. The `CIOCV_FLAG_CHECK_INPUT` determines if the `index` refers to an input or an output. Special values for the parameters, are listed below.

The `flags` parameter alters the behaviour of the opcode. If negative, the opcode checks the `scriptPubkey` of an input; otherwise, it checks the `scriptPubkey` of an output. The following value for the `flags` is currently the only one defined for inputs:

- `CCV_FLAG_CHECK_INPUT = -1`: makes the opcode check an input.

Non-negative values make the opcode check an output, and different values have different behaviour in the way the output's amount (`nValue`) is checked. The following values for the `flags` are currently defined for checking an output:

- `0`: default behavior, the (possibly residual) amount of this input must be present in the output. This amount
- `CCV_FLAG_IGNORE_OUTPUT_AMOUNT = 1`: For outputs, disables the default deferred checks on amounts defined below. Undefined when `CCV_FLAG_CHECK_INPUT` is present.
- `CCV_FLAG_DEDUCT_OUTPUT_AMOUNT = 2`: Fail if the amount of the output is larger than the amount of the input; otherwise, subtracts the value of the output from the value of the current input in future calls top `OP_CHECKCONTRACTVERIFY`.

The following values of the parameters are special values:
- If `pk` is empty, it is replaced with the NUMS x-only pubkey `0x50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0` defined in [BIP-0340](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki).
- If `pk` is `-1`, it is replaced with the current input's internal key.
- If `index` is `-1`, it is replaced with the current input index.  
- If `data` is empty, the data tweak is skipped.
- If `taptree` is empty, the taptweak is skipped.
- If `taptree` is `-1`, the taptree of the current input is used for the taptweak.

The following additional deferred checks are performed after the validation of all inputs is completed:
- The amount of each output must be at least equal to the sum of the amount of all the inputs that have a `CCV` for that output with the default flag (equal to `0`).
- No output that is a target of `CCV_FLAG_DEDUCT_OUTPUT_AMOUNT` can also be the target of another `OP_CHECKCONTRACTVERIFY`, unless it's with the `CCV_FLAG_IGNORE_OUTPUT_AMOUNT`.

### Pseudocode

Semantics (initialization before input evaluation):
```python
  for in_index in range(n_inputs)
    in_ccv_amount[in_index] = inputs[in_index].amount

  for out_index in range(n_outputs)
    out_min_amount[out_index] = 0
```


Semantics (per input):

```python
if flags < CCV_FLAG_CHECK_INPUT or flags > CCV_FLAG_DEDUCT_OUTPUT_AMOUNT:
  return success()  # undefined flags are OP_SUCCESS

if index == -1:
  index = current_input_index

if flags == CCV_FLAG_CHECK_INPUT:
  if index < 0 or index >= n_inputs:
    return fail()

  target = inputs[index].scriptPubKey
else:
  if index < 0 or index >= n_outputs:
    return fail()

  target = outputs[index].scriptPubKey

if taptree == <-1>:
  taptree = current_input_taptree

if pk == <0>:
  result = BIP340_NUMS_KEY
elif pk == <-1>:
  result = current_input_internal_key 
elif len(pk) == 32:
  result = pk
else:
  return fail()

if data != <0>:
  if len(data) != 32:
    return fail()

  result = tweak(result, data)

if len(taptree) != 0:
  if len(taptree) != 32:
    return fail()

  result = taptweak(result, taptree)

if target != P2TR(result)
  return fail()

if flags == 0:
  out_min_amount[index] += in_ccv_amount[current_input_index]
elif flags == CCV_FLAG_DEDUCT_OUTPUT_AMOUNT:
  if in_ccv_amount[current_input_index] > outputs[index].amount:
    return fail()
  in_ccv_amount[current_input_index] -= outputs[index].amount

stack.pop(5)  # drop all 5 stack elements
```

Semantics (deferred, checks after all inputs are validated successfully):

```python

  for out_index in range(n_outputs):
    if outputs[out_index].amount < out_min_amount[out_index]:
      return fail()

  if an_output_was_used_both_with_default_behavior_and_with_DEDUCT_OUTPUT_AMOUNT_semantics():
    return fail()
```

## Common patterns

Here are some examples for the most common combination of parameters.

### Check that some data is embedded in the current input

This is used to check data that was typically committed to in an output from a covenant-encumbered spend that produced the current input. 

```
<data=data> <index=-1> <pk=naked_pk> <taptree=-1> <flags=CCV_FLAG_CHECK_INPUT> CCV
```

### Check that a certain output with index `out_i` is a certain contract with specified data, preserving input amount

This might be used for a 1-to-1 or many-to-1 covenant-encumbered spend: one or several inputs are spent to an output with certain code and data.

```
<data=data> <index=out_i> <pk=output_naked_pk> <taptree=output_taptree> <flags=0> CCV 
```

### Check that the output with the same index as the current input is a certain contract with specified data, preserving input amount

This is a common pattern for 1-input-1-output contracts, as it allows flexibility when creating the transaction. Typically, this would be one after checking the current input's data using the [standard pattern](#check-that-some-data-is-embedded-in-the-current-input).

Many spends of this kind could easily be batched in the same transaction, possibly together with other unencumbered inputs/outputs.

```
<data=data> <index=-1> <pk=output_naked_pk> <taptree=output_taptree> <flags=0> CCV 
```

### Check that a certain output with index `out_i` is a a P2TR with a pubkey `output_pk`, preserving amount:

A simpler case where we just want the output to be a certain P2TR output, without any embedded data.

```
<data=<>> <index=out_i> <pk=output_pk> <taptree=<>> <flags=0> CCV
```


## Advanced patterns

The examples in this section use some less common use cases of `OP_CHECKCONTRACTVERIFY`.

### Check that some other input with index `in_i` is a specific contract with embedded data:

This allows to "read" the data of another input.

```
<data=input_data> <index=in_i> <pk=input_i_naked_pk> <taptree=input_taptree><flags=CCV_FLAG_CHECK_INPUT> CCV
```

### Subtract the amount of output `out_i` from the current input

This checks the _data_ and _program_ of an output, an subtracts the value of this output from the value of the current input. The residual value of the current input will be used in further calls to `OP_CHECKCONTRACTVERIFY`.

This allows the pattern of sending some amount to one or more specified destination, and then separately decide where to send any residual value.

```
<data=data> <index=out_i> <pk=output_naked_pk> <taptree=output_taptree> <flags=CCV_FLAG_DEDUCT_OUTPUT_AMOUNT> CCV 
```

### Check that a certain output with index `out_i` is a certain contract with specified data; don't check amount

This could be used to check _data_ and _program_ of an output, but not its amount (which might be either irrelevant, or is checked via a different introspection opcode).

```
<data=data> <index=out_i> <pk=output_naked_pk> <taptree=output_taptree> <flags=CCV_FLAG_IGNORE_OUTPUT_AMOUNT> CCV 
```

### Check that the input is sent exactly to the same scriptPubKey
This requires that the output with the same index as the current input is exactly the same script, and with the same amount.

```
<data=<>> <index=-1> <pk=-1> <taptree=-1> <flags=0> CCV
```
