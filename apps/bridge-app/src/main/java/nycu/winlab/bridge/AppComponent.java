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
package nycu.sdnnfv.bridge;

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

import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;

import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.DefaultTrafficTreatment;
import org.onosproject.net.flow.TrafficSelector;
import org.onosproject.net.flow.TrafficTreatment;

import org.onosproject.net.packet.PacketPriority;
import org.onosproject.net.packet.PacketService;
import org.onosproject.net.packet.PacketProcessor;
import org.onosproject.net.packet.PacketContext;
import org.onosproject.net.packet.InboundPacket;

import org.onlab.packet.Ethernet;
import org.onlab.packet.IPv4;
import org.onlab.packet.Ip4Address;
import org.onlab.packet.MacAddress;

import org.onosproject.net.PortNumber;
import org.onosproject.net.ConnectPoint;
import org.onosproject.net.DeviceId;

import org.onosproject.net.flow.FlowRuleService;
import org.onosproject.net.flow.DefaultFlowRule;
import org.onosproject.net.flow.FlowRule;

// import org.onosproject.net.packet.OutboundPacket;
// import org.onosproject.net.packet.DefaultOutboundPacket;

// import org.onosproject.net.Device;
import org.onosproject.net.device.DeviceService;
// import java.nio.ByteBuffer;

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

    // private LearningBridgeProcessor processor = new LearningBridgeProcessor();
    private ApplicationId appId;
    private Map<DeviceId, Map<MacAddress, PortNumber>> bridgeTable = new HashMap<>();
    private DeviceId[] devices = {
        DeviceId.deviceId("of:0000000000000001"),
        DeviceId.deviceId("of:0000000000000002"),
        DeviceId.deviceId("of:0000f6d0422f5543"),
    };
    private MacAddress[] mac = {
        MacAddress.valueOf("02:01:01:01:01:01"),
        MacAddress.valueOf("5A:3C:91:B4:7E:2F"),
    };

    @Activate
    protected void activate() {

        // register your app
        appId = coreService.registerApplication("nycu.sdnnfv.bridge");

        
        installRule(devices[0], mac[0], PortNumber.portNumber(2));
        installRule(devices[0], mac[1], PortNumber.portNumber(3));

        installRule(devices[1], mac[0], PortNumber.portNumber(3));
        installRule(devices[1], mac[1], PortNumber.portNumber(1));

        installRule(devices[2], mac[0], PortNumber.portNumber(1));
        installRule(devices[2], mac[1], PortNumber.portNumber(1));
        
        // // add a packet processor to packetService
        // packetService.addProcessor(processor, PacketProcessor.director(2));
        // // install a flowrule for packet-in
        // TrafficSelector.Builder selector = DefaultTrafficSelector.builder();
        // selector.matchEthType(Ethernet.TYPE_IPV4);
        // packetService.requestPackets(selector.build(), PacketPriority.REACTIVE, appId);

        // selector = DefaultTrafficSelector.builder();
        // selector.matchEthType(Ethernet.TYPE_IPV6);
        // packetService.requestPackets(selector.build(), PacketPriority.REACTIVE, appId);

        log.info("Started");
    }

    @Deactivate
    protected void deactivate() {

        // remove flowrule installed by your app
        flowRuleService.removeFlowRulesById(appId);

        // remove your packet processor
        // packetService.removeProcessor(processor);
        // processor = null;

        // remove flowrule you installed for packet-in
        TrafficSelector.Builder selector = DefaultTrafficSelector.builder();
        selector.matchEthType(Ethernet.TYPE_IPV4);
        packetService.cancelPackets(selector.build(), PacketPriority.REACTIVE, appId);

        selector = DefaultTrafficSelector.builder();
        selector.matchEthType(Ethernet.TYPE_IPV6);
        packetService.cancelPackets(selector.build(), PacketPriority.REACTIVE, appId);

        log.info("Stopped");
    }
    
    // private class LearningBridgeProcessor implements PacketProcessor {

    //     @Override
    //     public void process(PacketContext context) {
    //         // Stop processing if the packet has been handled, since we
    //         // can't do any more to it.
    //         // if (context.isHandled()) {
    //         //     return;
    //         // }
    //         InboundPacket pkt = context.inPacket();
    //         Ethernet ethPkt = pkt.parsed();

    //         if (ethPkt == null) {
    //             return;
    //         }

    //         if (ethPkt.getEtherType() != Ethernet.TYPE_IPV6 && ethPkt.getEtherType() != Ethernet.TYPE_IPV4) {
    //             return;
    //         }

    //         DeviceId recDevId = pkt.receivedFrom().deviceId();
    //         PortNumber recPort = pkt.receivedFrom().port();
    //         MacAddress srcMac = ethPkt.getSourceMAC();
    //         MacAddress dstMac = ethPkt.getDestinationMAC();

    //         // rec packet-in from new device, create new table for it
    //         if (bridgeTable.get(recDevId) == null) {
    //             bridgeTable.put(recDevId, new HashMap<>());
    //         }
    //     }
    // }

    // private void packetOut(PacketContext context, PortNumber port) {
    //     context.treatmentBuilder().setOutput(port);
    //     context.send();
    // }

    private void installRule(DeviceId deviceId, MacAddress dstMac, PortNumber outPort) {
        log.info("The device {} find MacAddress {} on port{}, install flow rule...", deviceId.toString(), dstMac.toString(), outPort.toString());
        TrafficSelector selectorBuilder = DefaultTrafficSelector.builder()
            .matchEthDst(dstMac)
            .build();

        TrafficTreatment treatment = DefaultTrafficTreatment.builder()
            .setOutput(outPort)
            .build();

        FlowRule flowRule = DefaultFlowRule.builder()
            .forDevice(deviceId)
            .fromApp(appId)
            .withSelector(selectorBuilder)
            .withTreatment(treatment)
            .makePermanent()
            .withPriority(20)
            .build();

        flowRuleService.applyFlowRules(flowRule);
    }
// ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

}