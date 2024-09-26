# **Assignment 1: HTTP Proxy**
## **Introduction: The Hypertext Transfer Protocol**
Request and response messages share a common basic format:
- An initial line (a request or response line, as defined below)
- Zero or more header lines
- A blank line (CRLF)
- An optional message body.

The initial line and header lines are each followed by a &quot;carriage-return line-feed&quot; (\r\n) signifying the end-of-line.

  


```
HTTP/1.0 200 OK

Content-Length: 69

Cache-Control: max-age=31536000

Last-Modified: Wed, 31 Jan 2024 17:36:49 GMT

Content-Type: text/html

Date: Wed, 31 Jan 2024 17:36:49 GMT

(More HTTP headers...)

Content-Type: text/html

<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>
```


You will only be responsible for implementing the GET method. 

All other request methods received by the proxy should elicit a &quot;Not Implemented&quot; (501) error 

### **Listening**
When your proxy starts, the first thing is to establish a socket connection that it can use to listen for incoming connections. 

Your proxy should listen on the port specified from the command line and wait for incoming client connections. 

Each new client request is accepted, and a new process is spawned using fork() to handle the request. 

There should be a reasonable limit on the number of processes that your proxy can create (e.g., 100). 

Once a client has connected, the proxy should read data from the client and then check for a properly-formatted HTTP request -- but don&#39;t worry, we have provided you with libraries that parse the HTTP request lines and headers. 
Specifically, you will use our libraries to ensure that the proxy receives a request that contains a valid request line:

&lt;METHOD&gt; &lt;URL&gt; &lt;HTTP VERSION&gt;

All other headers just need to be properly formatted:

&lt;HEADER NAME&gt;: &lt;HEADER VALUE&gt;

In this assignment, client requests to the proxy must be in their absolute URI form 

An invalid request, or headers are not properly formatted for parsing.. i.e. &quot;Bad Request&quot; (400) 
"HTTP/1.0 400 Bad Request\r\n\r\n".

&quot;Not Implemented&quot; (501) for valid HTTP methods other than GET. 
  

### **Parsing Library**
 The library can parse the request into a structure called ParsedRequest which has fields for things like the host name (domain name) and the port. 
 
 It also parses the custom headers into a set of ParsedHeader structs which each contain a key and value corresponding to the header. 
 
 You can lookup headers by the key and modify them. 
 
 The library can also recompile the headers into a string given the information in the structs.

verify that the headers are in the correct format since the parsing functions return error codes if this is not the case.


### **Parsing the URL**

Once the proxy sees a valid HTTP request, it will need to parse the requested URL. 

The proxy needs at least three pieces of information: the requested host and port, and the requested path. 

If the hostname indicated in the absolute URL does not have a port specified, you should use the default HTTP port 80.

### **Getting Data from the Remote Server**

Once the proxy has parsed the URL, it can make a connection to the requested host (using the appropriate remote port, or the default of 80 if none is specified) 

and send the HTTP request for the appropriate resource. The proxy should always send the request in the 
relative URL + Host header format 
regardless of how the request was received from the client:

 Accept from client:

GET http://www.jhu.edu/ HTTP/1.0

Send to remote server:

GET / HTTP/1.0

Host: www.jhu.edu

Connection: close

(Additional client specified headers, if any...)

Note that we always send HTTP/1.0 flags and a Connection: close header to the server, so that it will close the connection after its response is fully transmitted, as opposed to keeping open a persistent connection. 

So while you should pass the client headers you receive on to the server, **you should make sure you replace any Connection header received from the client with one specifying close, as shown. To add new headers or modify existing ones, use the HTTP Request Parsing Library we provide.**


### **Returning Data to the Client**

After the response from the remote server is received, the proxy should send the response message as-is to the client via the appropriate socket. To be strict, the proxy would be required to ensure a Connection: close is present in the server&#39;s response to let the client decide if it should close it&#39;s end of the connection after receiving the response. However, checking this is not required in this assignment for the following reasons. First, a well-behaving server would respond with a Connection: close anyway given that we ensure that we sent the server a close token. Second, we configure Firefox to always send a Connection: close by setting keepalive to false. Finally, we wanted to simplify the assignment so you wouldn&#39;t have to parse the server response.

### **Testing Your Proxy**

Run your client with the following command:

./proxy &lt;port&gt;, where port is the port number that the proxy should listen on. As a basic test of functionality, try requesting a page using telnet:

telnet localhost &lt;port&gt;

Trying 127.0.0.1...

Connected to localhost.localdomain (127.0.0.1).

Escape character is &#39;^]&#39;.

GET http://www.dpgraph.com/ HTTP/1.0

If your proxy is working correctly, the headers and HTML of the webpase should be displayed on your terminal screen. Notice here that we request the absolute URL (http://www.dpgraph.com/) instead of just the relative URL (/). A good sanity check of proxy behavior would be to compare the HTTP response (headers and body) obtained via your proxy with the response from a direct telnet connection to the remote server. Additionally, try requesting a page using telnet concurrently from two different shells.

For a slightly more complex test, you can configure your web browser to use your proxy server as its web proxy. See the section below for details.

## Test Environment
Here are some debugging tips. If you are still having trouble, ask a question on Piazza or see an instructor during office hours.

* Different OSes might slightly change in the way they implement the systemcalls. As Gradescope uses Ubuntu >= 20.04, make sure your code also works and covers all the requirements on Ubuntu. For this purpose, you can follow the instruction on the assignments repository README file to quickly set-up an Ubuntu virtual machine on your Laptop/PC. But in general, you may use any of these systems for this assignment:
    1. Any system with a recent Linux OS installed
    2. Any MAC system (Intel/M1/M2)
    3. Windows Subsystem for Linux (WSL)
    4. CS Undergrad/Masters servers
    5. The provided Multipass VM environment (see the root repository README file)

## **Configuring a Web Browser to Use a Proxy**

### **Firefox**

**Version 10.x:**

1. Select Tools-&gt;Options (or Edit-&gt;Preferences) from the menu.
2. Click on the &#39;Advanced&#39; icon in the Options dialog.
3. Select the &#39;Network&#39; tab, and click on &#39;Settings&#39; in the &#39;Connections&#39; area.
4. Select &#39;Manual Proxy Configuration&#39; from the options available. In the boxes, enter the hostname and port where proxy program is running.




## **Socket Programming**

In order to build your proxy you will need to learn and become comfortable programming sockets. The Berkeley sockets library is the standard method of creating network systems on Unix. There are a number of functions that you may need or find useful for this assignment:

- Parsing addresses:
  - inet\_addr

    - Convert a dotted quad IP address (such as 36.56.0.150) into a 32-bit address.

  - gethostbyname

    - Convert a hostname (such as www.jhu.edu) into a 32-bit address.

  - getservbyname

    - Find the port number associated with a particular service, such as FTP.

- Setting up a connection:
  - socket

    - Get a descriptor to a socket of the given type

  - connect

    - Connect to a peer on a given socket

  - getsockname

    - Get the local address of a socket

- Creating a server socket:
  - bind

    - Assign an address to a socket

  - listen

    - Tell a socket to listen for incoming connections

  - accept

    - Accept an incoming connection

- Communicating over the connection:
  - read/write

    - Read and write data to a socket descriptor

  - htons, htonl / ntohs , ntohl

    - Convert between host and network byte orders (and vice versa) for 16 and 32-bit values

You can find the details of these functions in the Unix man pages (most of them are in section 2) and in the Stevens _Unix Network Programming_ book, particularly chapters 3 and 4. Other sections you may want to browse include the client-server example system in chapter 5 (you will need to write both client and server code for this assignment) and the name and address conversion functions in chapter 9.

**Multi-Process Programming**

In addition to the Berkeley sockets library, there are some functions you will need to use for creating and managing multiple processes: fork, waitpid.

You can find the details of these functions in the Unix man pages:

- man 2 fork
- man 2 waitpid

**Links:**

- [Guide to Network Programming Using Sockets](http://beej.us/guide/bgnet/)
- [HTTP Made Really Easy- A Practical Guide to Writing Clients and Servers](http://www.jmarshall.com/easy/http/)
- [Wikipedia page on fork()](http://en.wikipedia.org/wiki/Fork_(operating_system))
