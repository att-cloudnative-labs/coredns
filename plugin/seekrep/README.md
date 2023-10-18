# cancel

## Name

*seekrep* - converts hosts with seekr prefix to the associated k8s service hostname

## Description

The *seekrep* plugin converts a k8s service hostname that has the prefix *seekrep#* to the hostname without the prefix. This effectively creates a wildcard for the number *#* and allows multiple target hostnames for the same service so that unique hostnames can be leveraged for connection pooling and endpoint distribution.

## Syntax

~~~ txt
seekrep
~~~

## Examples

~~~ corefile
example.org {
    seekrep
    kubernetes
    whoami
}
~~~
