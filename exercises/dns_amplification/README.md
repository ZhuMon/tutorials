# DNS_Amplification
* based on https://github.com/p4lang/tutorials/tree/master/exercises/basic
* usage:
  * 進入mininet
    ```
    make
    ```
  * 呼叫xterm
    ```
    mininet> xterm h1 h2 h3
    ```
   
  * 以 h3 為 dns server，在 h3 的 xterm 輸入
    ```
    python dns_server.py dns0313_2_onlyDNS.pcapng
    ```
    
  * 以 h1 為 victim，在 h1 的 xterm 輸入
    ```
    python victim.py
    ```
  
  * 以 h2 為 attacker，在 h2 的 xterm 輸入
    ```
    python attacker.py 10.0.3.3 10.0.1.1 dns0313_2_onlyDNS.pcapng
    ```
* dns_server.py
  * 接收來自 client 的 packet 
  * 在 pcap 檔裡找到相對應的 packet
      * 以transaction ID 與 qd (question section)進行比對
  * 重新包裝後送回client
      * 以 mininet 設置的 IP 取代 pcap 檔裡的 IP
          * ex: 124.132.24.12 -> 10.0.1.1
* victim.py
  * 接收 dns server 傳送的封包
  * print 封包

* attacker.py
  * 從 pcap 檔裡隨機找到一個 DNS packet
  * 重新包裝後，將 IP 的 src 位址填上 victim 的 IP，送給 server
  * print 偽造的封包
