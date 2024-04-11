# Overview

This directory contains code and results to execute the following three scenarios of data exchange operation in edge-based crypto offloading:

    1. No Offload - No offloading of ABE computations by Di and Dj

    2. Offload using reference protocol - Di offloads ABE computations to SAi and Dj offloads ABD computations to SAj

    3. Offload using enhanced protocol - SAi sends ABE output directly to SAj for ABD computations

The entire implementation is split into two steps:

    Step 1 - Executes only ABE operations to calculate latency and energy savings by offloading them to edge device.

    Step 2 - Executes the end-to-end data exchange protocol to calculate latency and energy savings on the end device which places a request for data. Currently, the results for plaintext of size 32 B using CPABE library are available only.