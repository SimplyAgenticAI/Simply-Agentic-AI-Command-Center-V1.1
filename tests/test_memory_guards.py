"""V13.9 memory guards: ffmpeg is thread-capped (it otherwise spawns a thread
per host CPU, each holding frames in RAM) and one clip renders at a time.
(File must sort after test_client_crud — conftest's auth_client wants to be
the first registration.)"""
import app as app_module


def test_ff_limit_caps_threads_and_keeps_output_last():
    args = app_module._ff_limit(["-y", "-ss", "1", "-i", "a.mp4", "-i", "b.mp4", "-c:v", "libx264", "out.mp4"])
    t = str(app_module.FFMPEG_THREADS)
    assert args[-1] == "out.mp4" and args[-3:-1] == ["-threads", t]
    # every input gets a decoder cap right before its -i
    assert [args[i - 2:i] for i, a in enumerate(args) if a == "-i"] == [["-threads", t], ["-threads", t]]
    assert args[:4] == ["-filter_threads", t, "-filter_complex_threads", t]


def test_one_clip_render_at_a_time_by_default():
    assert app_module._VC_RENDER_SEM._value == 1
