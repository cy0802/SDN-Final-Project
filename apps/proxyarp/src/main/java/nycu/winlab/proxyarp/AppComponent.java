/*
 * Copyright 2024-present Open Networking Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package nycu.sdnnfv.proxyarp;

import org.onosproject.cfg.ComponentConfigService;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;

import org.onosproject.net.packet.PacketPriority;
import org.onlab.packet.IpPrefix;
import org.onosproject.net.packet.PacketService;
import org.onosproject.net.packet.PacketProcessor;
import org.onosproject.net.packet.PacketContext;
import org.onosproject.net.packet.InboundPacket;

import org.onosproject.net.ConnectPoint;
import org.onosproject.net.Annotations;
import org.onosproject.net.Port;

import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.DefaultTrafficTreatment;
import org.onosproject.net.flow.TrafficSelector;
import org.onosproject.net.flow.TrafficTreatment;

import org.onosproject.net.Device;
import org.onosproject.net.device.DeviceService;

import org.onlab.packet.Ethernet;
import org.onlab.packet.MacAddress;
import org.onlab.packet.IpAddress;
import org.onlab.packet.Ip6Address;
import org.onlab.packet.ARP;
import org.onlab.packet.IPv6;
import org.onlab.packet.ICMP6;
import org.onlab.packet.ndp.NeighborAdvertisement;
import org.onlab.packet.ndp.NeighborSolicitation;
import org.onlab.packet.ndp.NeighborDiscoveryOptions;

import java.util.List;
import org.onlab.packet.DeserializationException;
import java.lang.InterruptedException;

import org.onosproject.net.PortNumber;
import org.onosproject.net.DeviceId;

import org.onosproject.net.flow.FlowRuleService;
import org.onosproject.net.flow.FlowRule;
import org.onosproject.net.flow.DefaultFlowRule;

import org.onosproject.net.packet.OutboundPacket;
import org.onosproject.net.packet.DefaultOutboundPacket;

/**
 * Skeletal ONOS application component.
 */
@Component(immediate = true)
public class AppComponent {

    private final Logger log = LoggerFactory.getLogger(getClass());

    /** Some configurable property. */

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected ComponentConfigService cfgService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected CoreService coreService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected PacketService packetService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected FlowRuleService flowRuleService;
    
    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected DeviceService deviceService;

    private ProxyArpProcessor processor = new ProxyArpProcessor();
    private ApplicationId appId;
    private Map<IpAddress, MacAddress> macTable = new HashMap<>();
    private Map<Ip6Address, MacAddress> macTable6 = new HashMap<>();
    private Iterable<Device> devices;

    @Activate
    protected void activate() {

        // register your app
        appId = coreService.registerApplication("nycu.sdnnfv.proxyarp");

        // add a packet processor to packetService
        packetService.addProcessor(processor, PacketProcessor.director(2));

        // install a flowrule for packet-in
        TrafficSelector.Builder selectorPktIn = DefaultTrafficSelector.builder();
        selectorPktIn.matchEthType(Ethernet.TYPE_IPV4)
                .matchEthType(Ethernet.TYPE_IPV6);
        packetService.requestPackets(selectorPktIn.build(), PacketPriority.REACTIVE, appId);

        devices = deviceService.getAvailableDevices();

        macTable.clear();
        macTable6.clear();

        macTable.put(IpAddress.valueOf("192.168.63.1"), MacAddress.valueOf("02:01:01:01:01:01"));
        macTable6.put(Ip6Address.valueOf("fd63::1"), MacAddress.valueOf("02:01:01:01:01:01"));
        macTable.put(IpAddress.valueOf("192.168.70.40"), MacAddress.valueOf("02:01:01:01:01:01"));
        macTable6.put(Ip6Address.valueOf("fd70::40"), MacAddress.valueOf("02:01:01:01:01:01"));
        macTable.put(IpAddress.valueOf("172.16.40.69"), MacAddress.valueOf("02:01:01:01:01:01"));
        macTable6.put(Ip6Address.valueOf("2a0b:4e07:c4:40::69"), MacAddress.valueOf("02:01:01:01:01:01"));
        macTable.put(IpAddress.valueOf("192.168.50.1"), MacAddress.valueOf("02:01:01:01:01:01"));
        macTable6.put(Ip6Address.valueOf("fd50::1"), MacAddress.valueOf("02:01:01:01:01:01"));
        macTable.put(IpAddress.valueOf("172.16.40.2"), MacAddress.valueOf("5A:3C:91:B4:7E:2F"));
        macTable6.put(Ip6Address.valueOf("2a0b:4e07:c4:40::2"), MacAddress.valueOf("5A:3C:91:B4:7E:2F"));
        macTable.put(IpAddress.valueOf("172.16.40.1"), MacAddress.valueOf("02:01:01:01:01:02"));
        macTable6.put(Ip6Address.valueOf("2a0b:4e07:c4:40::1"), MacAddress.valueOf("02:01:01:01:01:02"));
        macTable.put(IpAddress.valueOf("192.168.70.253"), MacAddress.valueOf("02:42:C0:A8:46:FD"));
        macTable6.put(Ip6Address.valueOf("fd70::fe"), MacAddress.valueOf("02:42:C0:A8:46:FD"));
        macTable.put(IpAddress.valueOf("192.168.50.2"), MacAddress.valueOf("02:42:AC:01:00:01"));
        macTable6.put(Ip6Address.valueOf("fd50::2"), MacAddress.valueOf("02:42:AC:01:00:01"));
        macTable.put(IpAddress.valueOf("192.168.63.2"), MacAddress.valueOf("5A:3C:91:B4:7E:2E"));
        macTable6.put(Ip6Address.valueOf("fd63::2"), MacAddress.valueOf("5A:3C:91:B4:7E:2E"));
        macTable6.put(Ip6Address.valueOf("fe80::1:1ff:fe01:101"), MacAddress.valueOf("02:01:01:01:01:01"));
        macTable6.put(Ip6Address.valueOf("fe80::70d2:42ff:fe91:fca3"), MacAddress.valueOf("5A:3C:91:B4:7E:2E"));

        ARP testPkt = new ARP();
        testPkt.setSenderHardwareAddress(MacAddress.valueOf("02:01:01:01:01:01").toBytes())
            .setSenderProtocolAddress(IpAddress.valueOf("192.168.70.40").toOctets())
            .setTargetHardwareAddress(MacAddress.valueOf("00:00:00:00:00:00").toBytes())
            .setTargetProtocolAddress(IpAddress.valueOf("192.168.70.253").toOctets())
            .setOpCode(ARP.OP_REQUEST)
            .setHardwareType(ARP.HW_TYPE_ETHERNET)
            .setProtocolType(ARP.PROTO_TYPE_IP)
            .setHardwareAddressLength((byte) 6)
            .setProtocolAddressLength((byte) 4);
        Ethernet ethPkt = new Ethernet();
        ethPkt.setSourceMACAddress(MacAddress.valueOf("02:01:01:01:01:01"))
            .setDestinationMACAddress(MacAddress.BROADCAST)
            .setEtherType(Ethernet.TYPE_ARP)
            .setPayload(testPkt);
        for(int i = 0; i < 5; i++) {
            log.info("send ARP pkt " + i);
            packetOut(ethPkt, DeviceId.deviceId("of:0000e6c41f423949"), PortNumber.portNumber(3));
            packetOut(ethPkt, DeviceId.deviceId("of:0000e6c41f423949"), PortNumber.portNumber(2));
            try {
                Thread.sleep(1000);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                log.error("Thread was interrupted", e);
            }
        }
        log.info("Started");
    }

    @Deactivate
    protected void deactivate() {

        // remove flowrule installed by your app
        flowRuleService.removeFlowRulesById(appId);

        // remove your packet processor
        packetService.removeProcessor(processor);
        processor = null;

        // remove flowrule you installed for packet-in
        TrafficSelector.Builder selector = DefaultTrafficSelector.builder();
        selector.matchEthType(Ethernet.TYPE_IPV4)
                .matchEthType(Ethernet.TYPE_IPV6);
        packetService.cancelPackets(selector.build(), PacketPriority.REACTIVE, appId);

        log.info("Stopped");
    }

    public class Ip6Pair {
        public final Ip6Address srcIp;
        public final Ip6Address targetIp;

        public Ip6Pair(Ip6Address srcIp, Ip6Address targetIp) {
            this.srcIp = srcIp;
            this.targetIp = targetIp;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) {
                return true;
            }
            if (o == null || getClass() != o.getClass()) {
                return false;
            }
            Ip6Pair ip6Pair = (Ip6Pair) o;
            return srcIp.equals(ip6Pair.srcIp) && targetIp.equals(ip6Pair.targetIp);
        }

        @Override
        public int hashCode() {
            return Objects.hash(srcIp, targetIp);
        }
    }

    public class IpPair {
        public final IpAddress srcIp;
        public final IpAddress targetIp;

        public IpPair(IpAddress srcIp, IpAddress targetIp) {
            this.srcIp = srcIp;
            this.targetIp = targetIp;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) {
                return true;
            }
            if (o == null || getClass() != o.getClass()) {
                return false;
            }
            IpPair ipPair = (IpPair) o;
            return srcIp.equals(ipPair.srcIp) && targetIp.equals(ipPair.targetIp);
        }

        @Override
        public int hashCode() {
            return Objects.hash(srcIp, targetIp);
        }
    }

    private Map<IpPair, ConnectPoint> missPktStorage = new HashMap<>();
    private Map<Ip6Pair, ConnectPoint> missPktStorage6 = new HashMap<>();

    private class ProxyArpProcessor implements PacketProcessor {

        @Override
        public void process(PacketContext context) {
            // Stop processing if the packet has been handled, since we
            // can't do any more to it.
            // if (context.isHandled()) {
            //     return;
            // }
            InboundPacket pkt = context.inPacket();
            Ethernet ethPkt = pkt.parsed();

            if (ethPkt == null) {
                return;
            }

            if (ethPkt.getEtherType() == Ethernet.TYPE_IPV6) {
                IPv6 ipv6pkt = (IPv6) ethPkt.getPayload();
                if (ipv6pkt.getNextHeader() == IPv6.PROTOCOL_ICMP6) {
                    log.info("receive ICMP6 pkt");
                    handleNDP(pkt);
                }
            }

            if (ethPkt.getEtherType() == Ethernet.TYPE_ARP) {
                // log.info("receive ARP pkt");
                handleARP(pkt);
                // return;
            }

            return;
        }
    }

    private void handleNDP(InboundPacket pkt) {
        Ethernet ethPkt = pkt.parsed();
        IPv6 ipv6pkt = (IPv6) ethPkt.getPayload();
        ICMP6 icmp6pkt = (ICMP6) ipv6pkt.getPayload(); 
        Ip6Address srcIp6 = Ip6Address.valueOf(ipv6pkt.getSourceAddress());
        MacAddress srcMac = ethPkt.getSourceMAC();

        if (icmp6pkt.getIcmpType() == ICMP6.NEIGHBOR_ADVERTISEMENT) {
            // if (macTable6.get(srcIp6) == null) {
            //     if (srcIp6.equals(Ip6Address.valueOf("fd70::fe"))) {
            //         macTable6.put(srcIp6, srcMac);
            //         log.info("add " + srcMac + " / " + srcIp6 + " to macTable6");
            //     }
            // }
            // log.info("receive neighbor advertisement");
            // log.info("\ticmp6: " + icmp6pkt.toString());
            // NeighborAdvertisement neighborAd = (NeighborAdvertisement) icmp6pkt.getPayload();
            // log.info("\tneighbor advertisement: " + neighborAd.toString());

            
            // Ip6Address dstIp6 = Ip6Address.valueOf(ipv6pkt.getDestinationAddress());
            // Ip6Pair ip6Pair = new Ip6Pair(srcIp6, dstIp6);
            // log.info("\tsrc IP: " + srcIp6 + " / dst IP: " + dstIp6);
            // log.info("\tsrc MAC: " + srcMac + " / dst MAC: " + ethPkt.getDestinationMAC());
            // if (missPktStorage6.get(ip6Pair) == null) {
            //     return;
            // }
            
            // log.info("add " + srcMac + " to macTable6");
            // DeviceId targetDeviceId = missPktStorage6.get(ip6Pair).deviceId();
            // PortNumber outport = missPktStorage6.get(ip6Pair).port();
            // missPktStorage6.remove(ip6Pair);
            // packetOut(ethPkt, targetDeviceId, outport);
            // log.info("RECV REPLY. Requested MAC = " + srcMac + " / device = " + targetDeviceId + " / port = " + outport);
        } else if (icmp6pkt.getIcmpType() == ICMP6.NEIGHBOR_SOLICITATION) {
            // log.info("receive neighbor solicitation");
            // log.info("\ticmp6: " + icmp6pkt.toString());
            NeighborSolicitation neighborSol = (NeighborSolicitation) icmp6pkt.getPayload();
            // log.info("\tneighbor solicitation: " + neighborSol.toString());
            // MacAddress srcMac = ethPkt.getSourceMAC();
            // Ip6Address srcIp6 = Ip6Address.valueOf(ipv6pkt.getSourceAddress());
            Ip6Address targetIp6 = Ip6Address.valueOf(neighborSol.getTargetAddress());

            if (macTable6.get(targetIp6) == null) {
                // // table miss, flood the NDP to edge port
                // Ip6Pair ip6Pair = new Ip6Pair(srcIp6, targetIp6);
                // if (missPktStorage6.get(ip6Pair) != null) {
                //     // still waiting for the response, drop this one
                //     return;
                // }
                // missPktStorage6.put(ip6Pair, pkt.receivedFrom());
                // IpAddress targetIp = IpAddress.valueOf(IpAddress.Version.INET6, targetIp6.toOctets());
                // if (targetIp.equals(IpAddress.valueOf("fd70::fe"))) {
                //     log.info("send neighbor advertisement");
                //     packetOut(ethPkt, DeviceId.deviceId("of:0000e6c41f423949"), PortNumber.FLOOD);
                //     // packetOut(ethPkt, DeviceId.deviceId("of:0000e6c41f423949"), PortNumber.portNumber(3));
                // } 
                // // log.info("TABLE MISS. Send request to edge ports");
                log.info("TABLE MISS. Requested IP = " + targetIp6);
            } else {
                if (targetIp6.equals(Ip6Address.valueOf("fd70::fe"))) {
                    log.info("send neighbor solicitation");
                    packetOut(ethPkt, DeviceId.deviceId("of:0000e6c41f423949"), PortNumber.portNumber(2));
                    packetOut(ethPkt, DeviceId.deviceId("of:0000e6c41f423949"), PortNumber.portNumber(3));
                }
                // table hit, reply NDP to the device
                Ethernet ethPktReply = NeighborAdvertisement.buildNdpAdv(targetIp6, macTable6.get(targetIp6), ethPkt);
                IPv6 ipv6Reply = (IPv6) ethPktReply.getPayload();
                ipv6Reply.setHopLimit((byte) 255);
                ethPktReply.setPayload(ipv6Reply);
                packetOut(ethPktReply, pkt.receivedFrom().deviceId(), pkt.receivedFrom().port());
                log.info("TABLE HIT. Requested MAC = " + macTable6.get(targetIp6) + " for " + targetIp6);
            }
        }
    }

    private void handleARP(InboundPacket pkt) {
        Ethernet ethPkt = pkt.parsed();
        ARP arpPkt = (ARP) ethPkt.getPayload();
        MacAddress arpSrcMac = MacAddress.valueOf(arpPkt.getSenderHardwareAddress());
        MacAddress arpTargetMac = MacAddress.valueOf(arpPkt.getTargetHardwareAddress());
        IpAddress arpSrcIp = IpAddress.valueOf(IpAddress.Version.INET, arpPkt.getSenderProtocolAddress());
        IpAddress arpTargetIp = IpAddress.valueOf(IpAddress.Version.INET, arpPkt.getTargetProtocolAddress());

        DeviceId deviceId = pkt.receivedFrom().deviceId();
        PortNumber inPort = pkt.receivedFrom().port();
        // if (macTable.get(arpSrcIp) == null && arpSrcIp.equals(IpAddress.valueOf("192.168.70.253"))) {
        //     macTable.put(arpSrcIp, arpSrcMac);
        //     log.info("add " + arpSrcMac + " / " + arpSrcIp + " to macTable");
        // }

        if (arpPkt.getOpCode() == ARP.OP_REPLY) {
            // // receive reply
            // // the target IP of reply pkt is the src IP for the request pkt
            // IpPair ipPair = new IpPair(arpTargetIp, arpSrcIp);
            // if (missPktStorage.get(ipPair) == null) {
            //     return;
            // }
            // DeviceId targetDeviceId = missPktStorage.get(ipPair).deviceId();
            // PortNumber outport = missPktStorage.get(ipPair).port();
            // missPktStorage.remove(ipPair);
            // // TODO: add port
            // packetOut(ethPkt, targetDeviceId, outport);
            // log.info("RECV REPLY. Requested MAC = " + arpSrcMac);
        } else if (arpPkt.getOpCode() == ARP.OP_REQUEST) {
            if (macTable.get(arpTargetIp) == null) {
                // // table miss, flood the ARP to edge port
                // IpPair ipPair = new IpPair(arpSrcIp, arpTargetIp);
                // if (missPktStorage.get(ipPair) != null) {
                //     // still waiting for the response, drop this one
                //     return;
                // }
                // missPktStorage.put(ipPair, pkt.receivedFrom());
                // for (Device device: devices) {
                // if (arpTargetIp.equals(IpAddress.valueOf("192.168.70.253"))) {
                //     log.info("send ARP pkt IPv4");
                //     packetOut(ethPkt, DeviceId.deviceId("of:0000e6c41f423949"), PortNumber.FLOOD);
                //     // packetOut(ethPkt, DeviceId.deviceId("of:0000e6c41f423949"), PortNumber.portNumber(3));
                // }
                // }
                // log.info("TABLE MISS. Send request to edge ports");
            } else {
                // table hit, reply ARP to the device
                packetOutWithMac(arpPkt, deviceId, inPort, macTable.get(arpTargetIp));
                log.info("TABLE HIT. Requested MAC = " + macTable.get(arpTargetIp) + " for " + arpTargetIp);
            }
        }
    }

    private void packetOutWithMac(ARP requestArp, DeviceId deviceId, PortNumber port, MacAddress mac) {
        // construct an ARP reply pkt
        ARP replyArp = requestArp.duplicate();
        replyArp.setSenderHardwareAddress(mac.toBytes())
            .setSenderProtocolAddress(requestArp.getTargetProtocolAddress())
            .setTargetHardwareAddress(requestArp.getSenderHardwareAddress())
            .setTargetProtocolAddress(requestArp.getSenderProtocolAddress())
            .setOpCode(ARP.OP_REPLY);

        Ethernet ethPkt = new Ethernet();
        ethPkt.setSourceMACAddress(replyArp.getSenderHardwareAddress())
            .setDestinationMACAddress(replyArp.getTargetHardwareAddress())
            .setEtherType(Ethernet.TYPE_ARP)
            .setPayload(replyArp);

        packetOut(ethPkt, deviceId, port);
    }

    private void packetOut(Ethernet ethPacket, DeviceId deviceId, PortNumber port) {
        TrafficTreatment treatment = DefaultTrafficTreatment.builder()
            .setOutput(port)
            .build();

        OutboundPacket outboundPacket = new DefaultOutboundPacket(
            deviceId,
            treatment,
            ByteBuffer.wrap(ethPacket.serialize())
        );

        packetService.emit(outboundPacket);
    }
}