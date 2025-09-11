# Performance run results

## Environment setup

The target blockchain is a single node Besu chain, running QBFT with 1 second block period, zero gas price. Can be set up using `resources/besu`.

## Result

Host spec: AWS EC2 c7a.4xlarge, 16 vCPU, 32 GB, AMD chip

```
=== LATENCY STATISTICS (20 runs) ===

Witness Generation Time:
  Average: 14.616404971s
  Min:     14.269506674s
  Max:     14.973092025s

Proving Time:
  Average: 6.506570495s
  Min:     6.421066478s
  Max:     6.572127866s

Transaction Time:
  Average: 1.05818808s
  Min:     1.007607945s
  Max:     2.008797438s

Total Transaction Latency:
  Average: 22.181163546s
  Min:     21.780311124s
  Max:     22.802677326s

=== END LATENCY STATISTICS ===
```