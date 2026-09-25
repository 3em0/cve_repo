# Show the out-of-bounds write itself: at every state-slot copy in clip_encode()
# compare the destination range against the size the host vector actually reserved.
#
# The vector is sized from the declared slot shapes (list_pockettts_state_slots),
# while each copy moves ggml_nbytes() of the real graph tensor into it, and no
# check guards offset + nb <= size.
set pagination off
set confirm off
set width 0
set breakpoint pending on

set $printed = 0
break /src/llamacpp/tools/mtmd/clip.cpp:5849
commands
    silent
    set $printed = $printed + 1
    set $size = (unsigned long long) (state_out._M_impl._M_finish - state_out._M_impl._M_start)
    set $end  = (unsigned long long) offset + (unsigned long long) nb
    if $printed <= 24
        printf "copy #%d  offset=%-8llu nb=%-7llu  buffer_size=%-8llu  write_end=%-8llu  overrun=%lld\n", $printed, (unsigned long long) offset, (unsigned long long) nb, $size, $end, (long long) $end - (long long) $size
    end
    continue
end

run
quit
