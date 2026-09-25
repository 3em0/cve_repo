# Forensics at the blocking point: dump the planted window and the surrounding heap
# when the allocator aborts, so we can tell whether the real structures also moved
# by 0x100 (relative geometry intact) or stayed put (planted offsets shifted).
#
# Addresses are stable because the lab entrypoint runs everything under setarch -R.
set pagination off
set confirm off
set width 0
handle SIGABRT stop

run

printf "\n=== abort reached ===\n"
printf "original-lab geometry expected the fenced chunk head at 0x55555ad0cb70\n"
printf "this host plants it at data()+0x1F86C0 = 0x55555ad0cc70\n"

printf "\n--- where the exploit expects the structure (0x55555ad0cb70) ---\n"
x/4xw 0x55555ad0cb70

printf "\n--- where this host plants it (0x55555ad0cc70) ---\n"
x/4xw 0x55555ad0cc70

printf "\n--- planted metadata block window (0x55555ad0cc70 - 0x20 .. + 0x60) ---\n"
x/32xw 0x55555ad0cc50

printf "\n--- search for the planted top size 0x1491 around the window ---\n"
find /w 0x55555ad08000, 0x55555ad30000, 0x1491

printf "\n--- backtrace ---\n"
bt 8

quit
