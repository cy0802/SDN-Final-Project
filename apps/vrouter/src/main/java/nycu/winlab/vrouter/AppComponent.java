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
package nycu.sdnnfv.vrouter;

import org.onosproject.cfg.ComponentConfigService;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;

import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.DefaultTrafficTreatment;
import org.onosproject.net.flow.TrafficSelector;
import org.onosproject.net.flow.TrafficTreatment;
// import org.onosproject.net.flow.instructions.Instructions;

import org.onosproject.net.packet.PacketPriority;
import org.onosproject.net.packet.PacketService;
import org.onosproject.net.packet.PacketProcessor;
import org.onosproject.net.packet.PacketContext;
import org.onosproject.net.packet.InboundPacket;
import org.onlab.packet.IpPrefix;

import org.onlab.packet.Ethernet;
import org.onlab.packet.IPv4;
import org.onlab.packet.IPv6;
import org.onlab.packet.MacAddress;

import org.onosproject.net.flow.FlowRuleService;

import org.onosproject.net.device.DeviceService;

import org.onosproject.net.intf.InterfaceService;
import org.onosproject.net.intf.Interface;

import org.onosproject.routeservice.RouteService;
// import org.onosproject.routeservice.ResolvedRoute;
// import org.onosproject.routeservice.NextHop;
// import org.onosproject.routeservice.RouteTableId;
import org.onosproject.routeservice.ResolvedRoute;
// import org.onosproject.routeservice.RouteInfo;
// import org.onosproject.net.Annotations;

import org.onosproject.net.ConnectPoint;
// import org.onosproject.net.intent.MultiPointToSinglePointIntent;
import org.onosproject.net.intent.PointToPointIntent;
import org.onosproject.net.intent.IntentService;
import org.onosproject.net.FilteredConnectPoint;
import org.onlab.packet.IpAddress;

import java.util.Optional;
// import java.util.Map;
// import java.util.Collection;
// import java.util.Set;
// import org.onosproject.routeservice.Route;

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

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected IntentService intentService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected InterfaceService interfaceService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected RouteService routeService;

    private VRouterProcessor processor = new VRouterProcessor();
    private ApplicationId appId;

    private MacAddress routerMac = MacAddress.valueOf("02:01:01:01:01:01");
    private MacAddress h1Mac = MacAddress.valueOf("5A:3C:91:B4:7E:2F");
    private IpAddress[] routerIp = {
        IpAddress.valueOf("192.168.63.1"),
        IpAddress.valueOf("192.168.70.40"),
        IpAddress.valueOf("192.168.50.1"),
        IpAddress.valueOf("fd63::1"),
        IpAddress.valueOf("fd70::40"),
        IpAddress.valueOf("fd50::1")
    };
    private IpAddress[] peerIp = {
        IpAddress.valueOf("192.168.63.2"),
        IpAddress.valueOf("192.168.70.253"),
        IpAddress.valueOf("192.168.50.2"),
        IpAddress.valueOf("fd63::2"),
        IpAddress.valueOf("fd70::fe"),
        IpAddress.valueOf("fd50::2")
    };
    private ConnectPoint[] peerCP = {
        ConnectPoint.deviceConnectPoint("of:0000000000000001/1"),
        ConnectPoint.deviceConnectPoint("of:0000e6c41f423949/3"),
        ConnectPoint.deviceConnectPoint("of:0000000000000002/2"), // TODO: check
        ConnectPoint.deviceConnectPoint("of:0000000000000001/1"),
        ConnectPoint.deviceConnectPoint("of:0000e6c41f423949/3"),
        ConnectPoint.deviceConnectPoint("of:0000000000000002/2"),
    };
    private ConnectPoint routerCP = ConnectPoint.deviceConnectPoint("of:0000000000000001/2");
    private ConnectPoint h1CP = ConnectPoint.deviceConnectPoint("of:0000000000000002/1");
    private IpAddress h1Ip4 = IpAddress.valueOf("172.16.40.2");
    private IpAddress h1Ip6 = IpAddress.valueOf("2a0b:4e07:c4:40::2");

    @Activate
    protected void activate() {

        // register your app
        appId = coreService.registerApplication("nycu.sdnnfv.vrouter");

        // add a packet processor to packetService
        packetService.addProcessor(processor, PacketProcessor.director(2));

        // install a flowrule for packet-in
        TrafficSelector.Builder selectorPktIn = DefaultTrafficSelector.builder();
        selectorPktIn.matchEthType(Ethernet.TYPE_IPV4);
        packetService.requestPackets(selectorPktIn.build(), PacketPriority.REACTIVE, appId);

        selectorPktIn = DefaultTrafficSelector.builder();
        selectorPktIn.matchEthType(Ethernet.TYPE_IPV6);
        packetService.requestPackets(selectorPktIn.build(), PacketPriority.REACTIVE, appId);

        for (int i = 0; i < peerIp.length; i++) {
            Boolean v4 = peerIp[i].isIp4();
            TrafficSelector.Builder selector = DefaultTrafficSelector.builder()
                .matchEthType(v4 ? Ethernet.TYPE_IPV4 : Ethernet.TYPE_IPV6)
                .matchEthDst(routerMac);
            if(v4) {
                selector.matchIPSrc(IpPrefix.valueOf(peerIp[i], 32))
                    .matchIPDst(IpPrefix.valueOf(routerIp[i], 32));
            } else {
                selector.matchIPv6Src(IpPrefix.valueOf(peerIp[i], 128))
                    .matchIPv6Dst(IpPrefix.valueOf(routerIp[i], 128));
            }

            TrafficTreatment treatment = DefaultTrafficTreatment.builder().build();
            PointToPointIntent intent = PointToPointIntent.builder()
                .appId(appId)
                .selector(selector.build())
                .treatment(treatment)
                .filteredEgressPoint(new FilteredConnectPoint(routerCP))
                .filteredIngressPoint(new FilteredConnectPoint(peerCP[i]))
                .priority(50)
                .build();
            intentService.submit(intent);
            selector = DefaultTrafficSelector.builder();
            if (v4) {
                selector.matchEthType(v4 ? Ethernet.TYPE_IPV4 : Ethernet.TYPE_IPV6)
                .matchIPSrc(IpPrefix.valueOf(routerIp[i], 32))
                .matchIPDst(IpPrefix.valueOf(peerIp[i], 32));
            } else {
                selector.matchEthType(v4 ? Ethernet.TYPE_IPV4 : Ethernet.TYPE_IPV6)
                .matchIPv6Src(IpPrefix.valueOf(routerIp[i], 128))
                .matchIPv6Dst(IpPrefix.valueOf(peerIp[i], 128));
            }
            intent = PointToPointIntent.builder()
                .appId(appId)
                .selector(selector.build())
                .treatment(treatment)
                .filteredEgressPoint(new FilteredConnectPoint(peerCP[i]))
                .filteredIngressPoint(new FilteredConnectPoint(routerCP))
                .priority(51+i)
                .build();
            intentService.submit(intent);
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
        selector.matchEthType(Ethernet.TYPE_IPV4);
        packetService.cancelPackets(selector.build(), PacketPriority.REACTIVE, appId);

        selector = DefaultTrafficSelector.builder();
        selector.matchEthType(Ethernet.TYPE_IPV6);
        packetService.cancelPackets(selector.build(), PacketPriority.REACTIVE, appId);

        intentService.getIntentsByAppId(appId).forEach(intent -> {
            intentService.withdraw(intent);
        });

        log.info("Stopped");
    }

    private class VRouterProcessor implements PacketProcessor {

        @Override
        public void process(PacketContext context) {
            // Stop processing if the packet has been handled, since we
            // can't do any more to it.
            // if (context.isHandled()) {
            //     return;
            // }
            InboundPacket pkt = context.inPacket();
            Ethernet ethPkt = pkt.parsed();

            if (ethPkt.getEtherType() != Ethernet.TYPE_IPV4 && ethPkt.getEtherType() != Ethernet.TYPE_IPV6) {
                return;
            }
            // log.info("Received packet: {}", ethPkt.toString());

            IpAddress dstIp;

            if (ethPkt.getEtherType() == Ethernet.TYPE_IPV4) {
                IPv4 ipv4Pkt = (IPv4) ethPkt.getPayload();
                dstIp = IpAddress.valueOf(ipv4Pkt.getDestinationAddress());
            } else {
                IPv6 ipv6Pkt = (IPv6) ethPkt.getPayload();
                dstIp = IpAddress.valueOf(IpAddress.Version.INET6, ipv6Pkt.getDestinationAddress());
            }

            if (inAS(dstIp)) {
                handleInASPkt(dstIp, context);
            } else {
                handleRouting(dstIp, context);
            }

            // Collection<ResolvedRoute> routes = routeService.getAllResolvedRoutes(IpPrefix.valueOf(dstIp, 32));
            // if (routes.isEmpty()) {
            //     log.warn("No route found for dst IP: {}", dstIp);
            //     return;
            // }
            // ResolvedRoute route = routes.iterator().next();

            // log.info("dstIp: " + dstIp.toString() + ", isIpv4 ? " + dstIp.isIp4());
        }

        private void handleRouting(IpAddress dstIp, PacketContext context) {
            log.info("handleRouting: " + dstIp);

            InboundPacket pkt = context.inPacket();

            // routeService.
            Optional<ResolvedRoute> optional = routeService.longestPrefixLookup(dstIp);
            if (!optional.isPresent()) {
                log.warn("No route found for dst IP: {}", dstIp);
                return;
            }
            ResolvedRoute route = optional.get();

            IpAddress nextHopIp = route.nextHop();
            MacAddress nextHopMac = route.nextHopMac();
            log.info("found route to {} via {}, mac: {}", dstIp, nextHopIp, nextHopMac);

            Interface intf = interfaceService.getMatchingInterface(nextHopIp);
            if (intf == null) {
                log.warn("No interface found for next hop IP: {}", nextHopIp);
                return;
            }
            ConnectPoint egressCP = intf.connectPoint();
            log.info("targetConnectPoint: " + egressCP.toString());

            TrafficSelector.Builder selector = DefaultTrafficSelector.builder();

            if (dstIp.isIp4()) {
                selector.matchEthType(Ethernet.TYPE_IPV4)
                    .matchIPDst(IpPrefix.valueOf(dstIp, 32));
            } else {
                selector.matchEthType(Ethernet.TYPE_IPV6)
                    .matchIPv6Dst(IpPrefix.valueOf(dstIp, 128));
            }

            TrafficTreatment treatment = DefaultTrafficTreatment.builder()
                .setEthSrc(routerMac)
                .setEthDst(nextHopMac)
                .build();

            PointToPointIntent intent = PointToPointIntent.builder()
                .appId(appId)
                .selector(selector.build())
                .treatment(treatment)
                .filteredEgressPoint(new FilteredConnectPoint(egressCP))
                .filteredIngressPoint(new FilteredConnectPoint(pkt.receivedFrom()))
                .priority(30)
                .build();
            intentService.submit(intent);
        }

        private void handleInASPkt(IpAddress dstIp, PacketContext context) {
            log.info("handleInASPkt: " + dstIp);
            ConnectPoint egress;
            MacAddress dstMac;
            Boolean isHost = dstIp.equals(h1Ip4) || dstIp.equals(h1Ip6);
            if (isHost) {
                egress = h1CP;
                dstMac = h1Mac;
            } else {
                egress = routerCP;
                dstMac = routerMac;
            }

            Boolean isRouter = false;
            for (IpAddress ip: routerIp) {
                if (ip.equals(dstIp)) {
                    isRouter = true;
                    break;
                }
            }
            if ((!isRouter) && (!isHost)) {
                return;
            }

            TrafficSelector.Builder selector = DefaultTrafficSelector.builder();
            if (dstIp.isIp4()) {
                selector.matchEthType(Ethernet.TYPE_IPV4)
                    .matchIPDst(IpPrefix.valueOf(dstIp, 32));
            } else {
                selector.matchEthType(Ethernet.TYPE_IPV6)
                    .matchIPv6Dst(IpPrefix.valueOf(dstIp, 128));
            }
            TrafficTreatment treatment = DefaultTrafficTreatment.builder()
                .setEthDst(dstMac)
                .build();
            PointToPointIntent intent = PointToPointIntent.builder()
                .appId(appId)
                .selector(selector.build())
                .treatment(treatment)
                .filteredEgressPoint(new FilteredConnectPoint(egress))
                .filteredIngressPoint(new FilteredConnectPoint(context.inPacket().receivedFrom()))
                .priority(40)
                .build();
            intentService.submit(intent);
        }

        private Boolean inAS(IpAddress ip) {
            if (ip.equals(IpAddress.valueOf("192.168.63.1"))) { return true; }
            if (ip.equals(IpAddress.valueOf("192.168.70.40"))) { return true; }
            if (ip.equals(IpAddress.valueOf("172.16.40.69"))) { return true; }
            if (ip.equals(IpAddress.valueOf("172.16.40.2"))) { return true; }
            if (ip.equals(IpAddress.valueOf("fd63::1"))) { return true; }
            if (ip.equals(IpAddress.valueOf("fd70::40"))) { return true; }
            if (ip.equals(IpAddress.valueOf("2a0b:4e07:c4:40::69"))) { return true; }
            if (ip.equals(IpAddress.valueOf("2a0b:4e07:c4:40::2"))) { return true; }
            return false;
        }
    }
}