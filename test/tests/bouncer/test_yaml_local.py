def test_yaml_local(bouncer, cb_stream_cfg_factory):
    cfg = cb_stream_cfg_factory()

    with bouncer(cfg) as cb:
        cb.wait_for_lines_fnmatch(
            [
                "*config does not contain LAPI key or certificate*",
            ]
        )
        cb.proc.wait(timeout=0.2)
        assert not cb.proc.is_running()

    config_local = {"api_key": "not-used", "api_url": "http://localhost/not-there"}

    with bouncer(cfg, config_local=config_local) as cb:
        cb.wait_for_lines_fnmatch(
            [
                "*connection refused*",
                "*terminating bouncer process*",
                "*bouncer stream halted*",
            ]
        )
