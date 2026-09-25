# Measure where the pocket-tts state buffer is copied in THIS environment.
#
# The original lab recorded (exp/pocketrce/README.md):
#     state_out chunk  0x55555ab144a0   (data at 0x55555ab144b0)
#     dest = data() + 2039812 = 0x55555ad064b4
#     up slot copy     0x18000 bytes
# If the numbers printed here differ, the heap layout is not the one the RCE
# artifact's planted words were calibrated against, and that alone explains a
# malloc abort instead of the planted-pointer chain.
set pagination off
set confirm off
set width 0
set breakpoint pending on

set $printed = 0
break /src/llamacpp/tools/mtmd/clip.cpp:5849
commands
    silent
    set $printed = $printed + 1
    if $printed <= 40
        printf "copy  nb=%llu offset=%llu data=%p target=%p\n", (unsigned long long) nb, (unsigned long long) offset, state_out._M_impl._M_start, (char *) state_out._M_impl._M_start + offset
    end
    continue
end

run
quit
