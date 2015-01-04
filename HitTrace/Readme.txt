LoopyTrace HitTrace
===================

This is a simple hit tracer, that instead of using breakpoints overwrites
instructions to be traced with an infinite loop to "trap" the execution
at the traced location. HitTrace then monitors the instruction pointers
of the traced process' threads, to see if any of the threads have been
"trapped" in one of the infinite loops. If so we have a "hit".

The advantage of this technique is that most types of anti-debug tricks
do not detect it. However, it will not work with program that use
checksumming or polymorhphic code.

Only the very first instruction of functions are traced. Functions are
searched for using a heuristic, which is not 100% accurate for all
programs and may cause crashes or instability (for instance some types of
jump tables can be incorrectly matched as functions and corrupted).
Also, HitTrace will only trace the first code section.

The reached memory regions is displayed in real time, and a full dump
of all reached functions can be saved in PE (.exe) format. Code that
was not reached is replaced with NOP (0x90) instructions.
