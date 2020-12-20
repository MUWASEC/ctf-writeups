# Description
SANS SEC760 IDA Pro Challenge

Binary: http://bit.ly/sec760babyheap
Target: nc http://babyheap.deadlisting.com 5760

To win: DM me a screenshot of target compromise, your source IP, & exploit code. 
First one to do this wins the IDA license! I will post when a winner is identified. Good luck!

# Solution
1.) from off-by-one to overwrite tcache-e->key for bypassing double free mitigation
2.) or using house of botcake technique for bypassing double free mitigation
3.) then do tcache poisoning