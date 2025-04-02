# Botnet🤖
A custom FRIENDLY implementation of a botnet attack.

## Brief explanation of attack  
There are two malicious host types: bot_node and bot_master.  
Bot master must command bot nodes in some unsuspicious way to spam ARP requests on some target IP during given time.  

# Modules  

## bot_master  
This module is responsible for periodically sending broadcast packages in the following format.  
![photo_2025-04-02_20-10-51](https://github.com/user-attachments/assets/8cd17a05-d3e9-450d-8a07-428eb26f518a)  
As you can see, the package has regular ARP format, but instead of source IP it has target_ip and instead of target IP it has attack_time.  
The key identifier for bot_nodes is SHA which should be some secret bot_master MAC that was chosen before setting this software in network.  
Importantly, bot_master should be installed on one machine in the network, cause otherwise it will be quite suspicious behaviour or lead to missidentification of packages by bot_nodes.  

To run this module simply call it with following format:  
``` $ bot_master.exe "<NIC_adapter_name>" <target_ip> <attack_time> <timeout> ```  

## bot_node  
This module is listening for packages that bot_master sends. As soon as, the package is delivered bot_node compares source hardware address with chose bot_master MAC and extracts target_ip and attack_time.  
Afterwards, it starts to send ARP packages on target_ip within given attack_time. Importantly, if bot_master's timeout is less than attack_time, the attack will be performed until bot_master is shut down.  
When bot_master shuts down, bot_node finishes its last load of ARP packages and continue to listen.  

To run this module simply call it with following format:  
```$ bot_node.exe "<NIC_adapter_name>" ```  

## Build  
Currently only windows build is supported. The system is resolved automatically.  
``` $ make ```  

# Eperiment  
Botnet was tested with following, not very comlicated network with 3 hosts.  
![bot_net_experiment drawio (5)](https://github.com/user-attachments/assets/829ed636-85db-4ddd-bc17-c8c568398ec8)  
The goal of the conducted experiment was to observe structure of bot_master packages and ARP spam from bot_node in wireshark on victim's pc.  
  
bot_node was listening on TPlink adapter with MAC as in the picture.  
```$ bot_node.exe "TPLINK usb adapter"```  
  
bot_master was sending packages with target_ip set to victim's machine IP, attack time 10 seconds and timeout period 5 seconds.  
```$ bot_master.exe "ASIX electron usb adapter" 192.168.0.33 10 5```  
  
Bot_master package:  
![image](https://github.com/user-attachments/assets/8f7588c2-7f2c-4f14-82af-0bc98faa6e4d)  
> btw 62:6f:74:6e:65:74 isn't just a number ;)

Bot_node ARP spam package:  
![image](https://github.com/user-attachments/assets/acc56aef-041f-4ee9-a2b0-55d6be50f8db)

You can see full dump with timestamps [here](https://drive.google.com/file/d/1Y0UhJ9RMOeUqpthg-sdcFYC-39zg-bDe/view?usp=sharing)  

