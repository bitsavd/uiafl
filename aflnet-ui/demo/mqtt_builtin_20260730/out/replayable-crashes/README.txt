Command line used to find this crash:

./afl-fuzz -d -i tutorials/mosquitto/in-mqtt -o /home/cym/桌面/datadisk/Industrial_Protocol_Fuzzing/mqtt/fuzz_runs/20260730_090800_mqtt_builtin_seeds_6h/out -m none -t 1000+ -N tcp://127.0.0.1/1886 -P MQTT -D 10000 -q 3 -s 3 -E -K -R -- mosquitto/src/mosquitto -p 1886

If you can't reproduce a bug outside of afl-fuzz, be sure to set the same
memory limit. The limit used for this fuzzing session was 0 B.

Need a tool to minimize test cases before investigating the crashes or sending
them to a vendor? Check out the afl-tmin that comes with the fuzzer!

Found any cool bugs in open-source tools using afl-fuzz? If yes, please drop
me a mail at <lcamtuf@coredump.cx> once the issues are fixed - I'd love to
add your finds to the gallery at:

  http://lcamtuf.coredump.cx/afl/

Thanks :-)
