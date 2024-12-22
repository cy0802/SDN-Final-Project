run:
	sudo docker compose up -d
	sudo apt update
	sudo apt install -y openvswitch-switch
	sudo ovs-vsctl add-br ovs1
	sudo ovs-vsctl set-controller ovs1 tcp:127.0.0.1:6653
	sudo ovs-docker add-port ovs1 eth3 RClient --ipaddress=192.168.63.2/24
	sudo docker exec RClient ip -6 addr add fd63::1/64 dev eth3
	sudo ovs-vsctl add-br ovs2
	sudo ovs-vsctl set-controller ovs2 tcp:127.0.0.1:6653
	sudo ovs-docker add-port ovs1 eth0 h1 --ipaddress=172.16.40.2/24
	sudo docker exec h1 ip -6 addr add 2a0b:4e07:c4:40::1/64 dev eth0

	sudo ip link add veth0 type veth peer name veth1
	sudo ovs-vsctl add-port ovs1 veth0
	sudo ip link set veth0 up
	PID=$$(docker inspect -f '{{.State.Pid}}' RMain) && \
	echo $$PID && \
	sudo ip link set veth1 netns $$PID && \
	sudo nsenter -t $$PID -n ip link set veth1 up
	sudo docker exec RMain ip link set veth1 up

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
	

