# @TEST-EXEC: zeek -C -r ${TRACES}/quic-with-several-tls-frames.pcapng ../../../__load__.zeek %INPUT
# @TEST-EXEC: btest-diff conn.log
