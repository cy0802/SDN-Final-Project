run:
	sudo docker compose up -d
	
	sudo ovs-vsctl add-br ovs1
	sudo ovs-vsctl set bridge ovs1 other-config:datapath-id=0000000000000001
	sudo ovs-vsctl set bridge ovs1 protocols=OpenFlow14
	sudo ovs-vsctl set-controller ovs1 tcp:127.0.0.1:6653
	sudo ovs-docker add-port ovs1 eth3 RClient --ipaddress=192.168.63.2/24
	sudo docker exec RClient ip -6 addr add fd63::2/64 dev eth3
	sudo docker exec RClient ip route replace default via 192.168.63.1 dev eth3
	sudo docker exec h2 ip route replace default via 172.17.40.1 dev eth0
	sudo docker exec h2 ip -6 route replace default via 2a0b:4e07:c4:140::1 dev eth0
	
	sudo ovs-vsctl add-br ovs2
	sudo ovs-vsctl set bridge ovs2 other-config:datapath-id=0000000000000002
	sudo ovs-vsctl set bridge ovs2 protocols=OpenFlow14
	sudo ovs-vsctl set-controller ovs2 tcp:127.0.0.1:6653
	sudo ovs-docker add-port ovs2 eth0 h1 --ipaddress=172.16.40.2/24 --macaddress=5A:3C:91:B4:7E:2F
	sudo docker exec h1 ip -6 addr add 2a0b:4e07:c4:40::69/64 dev eth0 
	sudo docker exec h1 ip route add default via 172.16.40.1
	sudo docker exec h1 ip -6 route add default via 2a0b:4e07:c4:40::1

	sudo ovs-vsctl add-port ovs2 vxlan1 -- set interface vxlan1 type=vxlan options:remote_ip=192.168.60.40

	sudo ip link add veth0 type veth peer name veth1
	sudo ip link set dev veth1 address 02:01:01:01:01:01
	sudo ovs-vsctl add-port ovs1 veth0
	sudo ip link set veth0 up
	PID=$$(docker inspect -f '{{.State.Pid}}' RMain) && \
	echo $$PID && \
	sudo ip link set veth1 netns $$PID && \
	sudo nsenter -t $$PID -n ip link set veth1 up
	sudo docker exec RMain ip link set veth1 up
	sudo docker exec RMain ip addr add 172.16.40.69/24 dev veth1
	sudo docker exec RMain ip -6 addr add 2a0b:4e07:c4:40::69/64 dev veth1
	sudo docker exec RMain ip addr add 192.168.63.1/24 dev veth1
	sudo docker exec RMain sysctl -w net.ipv6.conf.veth1.accept_dad=0
	sudo docker exec RMain sysctl -w net.ipv6.conf.all.forwarding=1
	sudo docker exec RMain ip -6 addr add fd63::1/64 dev veth1

	sudo ip link add veth2 type veth peer name veth3
	sudo ovs-vsctl add-port ovs1 veth2
	sudo ip link set veth2 up
	sudo ovs-vsctl add-port ovs2 veth3
	sudo ip link set veth3 up

clean:
	docker compose down
	sudo ovs-vsctl del-br ovs1
	sudo ovs-vsctl del-br ovs2
	sudo ip link del veth2
	
run-arp:
	cd /home/ycyyo/final-project/apps/proxyarp && make run-arp

rerun-arp:
	cd /home/ycyyo/final-project/apps/proxyarp && make rerun-arp

run-bridge:
	cd /home/ycyyo/final-project/apps/bridge-app && make run

rerun-bridge:
	cd /home/ycyyo/final-project/apps/bridge-app && make rerun

run-vrouter:
	cd /home/ycyyo/final-project/apps/vrouter && make run

rerun-vrouter:
	cd /home/ycyyo/final-project/apps/vrouter && make rerun
