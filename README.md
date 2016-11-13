# Dataview Raspberry Pi Automator
This project includes a Dataview Atomator for the Raspberry Pi.

## Currently Available Features

This automator currently supports the following operations:

* Turn the HDMI output off
* Turn the HDMI output on (requires sudo - see [#1](/../../issues/1))
* Starting Kodi
* Stopping Kodi

## Installing

Installation of the Raspberry Pi Automator can be more complicated than other automators if your operating system uses an outdated version of Python:

<pre>
$ python3 --version
Python 3.2.3
</pre>

If you do not have at least Python 3.4 and you have fully updated your Raspberry Pi please follow the [Python upgrade guide](https://github.com/wl-net/dataview-rpi-automator/wiki/Installation#installing-python-34).

## Generating a X.509 Server Certificate

In order to provide secure communications between the RPC consumer and the RPC server, TLS is utilized. You must create a X.509 Server Certificate for this to work.

<pre>
openssl genrsa -out server.pem 4096
openssl req -new -x509 -key server.pem -out cert.pem -days 730
</pre>

Please see the instructions on [how to generate a certificate](https://github.com/wl-net/dataview/wiki/Transports#generating-a-properly-formed-certificate) for information about how to fill out the questions openssl asks.

Once you have generated the private key and certificate, copy the certificate (cert.pem) to the machine the RPC consumer is operating from.

## Generating Authentication Token
You must generate an Authentication Token of at least 32 characters. You can use openssl with the rand tool as shown below.  
<pre>
$ openssl rand -hex 32
493152a14843198555759262f1bd767235789aebdcc5f1b1f8f2cd3a965c8c7a
</pre>

When you launch the automator script, be sure that the RPCSERVER_TOKEN environment variable is set.

<pre>
export RPCSERVER_TOKEN='GENERATED_TOKEN'
</pre>

## Launching automator

Be sure that you have generated the X.509 Server Certificate and exported the RPCSERVER_TOKEN environment variable, then:

<pre>
$ python3 automator.py --tlscert cert.pem --tlskey server.pem --host 0.0.0.0:8443
</pre>

NOTE: Make sure you are using python 3.4 to run the automator. If you build python as part of the installation process then use the following command:

<pre>
$ python3 automator.py --tlscert cert.pem --tlskey server.pem --host 0.0.0.0:8443
</pre>
