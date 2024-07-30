# ebpf examples to drop ping to 8.8.8.8


## compilation
```
make -j$(nproc)
```
## examples
### tc example
```
cd bin
sudo tc qdisc add dev ens192 clsact
./main-tc ens192
```

### xdp example with ringbuf
```
cd bin
sudo ./main-ringbuf ens192
```

### xdp example with perf event
```
cd bin
sudo ./main-perf-event ens192
```