# DNS_Server
* based on tutorials/exercises/basic
* usage:
  * 進入mininet
    ```
    make
    ```
  * 呼叫xterm
    ```
    xterm h1 h2
    ```
  * 以 h1 為 server，在 h1 的 xterm 輸入
    ```
    python dns_server.py dns0313_2_onlyDNS.pcapng
    ```
  * 以 h2 為 client，在 h2 的 xterm 輸入
    ```
    python dns_client.py 10.0.1.1 dns0313_2_onlyDNS.pcapng
    ```

* dns_server.py
  * 接收來自 client 的 packet 
  * 在 pcap 檔裡找到相對應的 packet
  * 重新包裝後送回client
* dns_client.py
  * 從 pcap 檔裡隨機找到一個 DNS packet
  * 重新包裝後，送給 server
  * 等待 server 回傳封包後，將封包顯示在螢幕上
