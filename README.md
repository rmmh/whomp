An attempt to reverse-engineer branch prediction on modern x86 processors (Haswell in particular).

Inspired by [Matt Godbolt's](http://xania.org/201602/haswell-and-ivy-btb) investigations.

It generates a function involving a long sequence of unconditional jumps. Theoretically, enough
jumps will eventually exceed the Branch Prediction Unit's capacity, causing BPU mispredicts.
Determining the sets of addresses that together force a mispredict should give information
on how they are stored.

In the current preliminary state, it finds that these addresses collide:

	0x10003f377
	0x1009bf376
	0x1008cb379
	0x100eef36d
	0x10071736e

Which seems very plausible! More work is necessary to understand the precise function.
