/**
 *    Copyright 2014, Columbia University.
 *    Homework 1, COMS E6998-10 Fall 2014
 *    Software Defined Networking
 *    Originally created by Shangjin Zhang, Columbia University
 * 
 *    Licensed under the Apache License, Version 2.0 (the "License"); you may
 *    not use this file except in compliance with the License. You may obtain
 *    a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 *    License for the specific language governing permissions and limitations
 *    under the License.
 **/

/**
 * Floodlight
 * A BSD licensed, Java based OpenFlow controller
 *
 * Floodlight is a Java based OpenFlow controller originally written by David Erickson at Stanford
 * University. It is available under the BSD license.
 *
 * For documentation, forums, issue tracking and more visit:
 *
 * http://www.openflowhub.org/display/Floodlight/Floodlight+Home
 **/

/**
 * @author Chao Chen
 */

package edu.columbia.cs6998.sdn.hw1;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.util.MACAddress;

import org.openflow.protocol.OFError;
import org.openflow.protocol.OFFlowMod;
import org.openflow.protocol.OFFlowRemoved;
import org.openflow.protocol.OFMatch;
import org.openflow.protocol.OFMessage;
import org.openflow.protocol.OFPacketIn;
import org.openflow.protocol.OFPacketOut;
import org.openflow.protocol.OFPort;
import org.openflow.protocol.OFType;
import org.openflow.protocol.action.OFAction;
import org.openflow.protocol.action.OFActionDataLayerDestination;
import org.openflow.protocol.action.OFActionDataLayerSource;
import org.openflow.protocol.action.OFActionNetworkLayerDestination;
import org.openflow.protocol.action.OFActionNetworkLayerSource;
import org.openflow.protocol.action.OFActionOutput;
import org.openflow.util.HexString;
import org.openflow.util.LRULinkedHashMap;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Hw1Switch implements IFloodlightModule, IOFMessageListener {
	protected static Logger log = LoggerFactory.getLogger(Hw1Switch.class);

	protected boolean fireWallActivated = true; // set TRUE to activate
												// firewall; FALSE to
												// deactivate.
	protected boolean loadBalanceActivated = false; // set TRUE to activate load
													// balance; FALSE to
													// deactivate

	// Server List used for Load Balance. Server information stored as
	// <ip,MACAddress> pair in the Array_list.
	protected ArrayList<String[]> serverList = new ArrayList<String[]>() {
		{
			add(new String[] { "10.0.0.2", "0a:00:22:22:22:22" });
			add(new String[] { "10.0.0.3", "0a:00:33:33:33:33" });
			// Servers added here
		}
	};
	// used for load balance. To store elephant flows of each server.
	// <serverMAC, list of hostMAC>
	protected Map<Long, ArrayList<Long>> serverToSrcMap;

	// Module dependencies
	protected IFloodlightProviderService floodlightProvider;

	// Stores the learned state for each switch
	protected Map<IOFSwitch, Map<Long, Short>> macToSwitchPortMap;

	// Store host MAC and it's destination: <HostMacaddr, list of destination
	// Mac>
	protected Map<Long, ArrayList<Long>> hostToDestMap;

	// Store src&dst of elephant flows on switches:
	// <Switch,ArrayList<[srcMac,dstMac]>>
	protected Map<IOFSwitch, ArrayList<String[]>> elephantFlowOnSwitchMap;

	// Stores the MAC address of hosts to block:
	// <Macaddr, Timestamp when it's blocked>
	protected Map<Long, Long> blacklist;

	// flow-mod - for use in the cookie
	public static final int HW1_SWITCH_APP_ID = 10;
	// LOOK! This should probably go in some class that encapsulates
	// the app cookie management
	public static final int APP_ID_BITS = 12;
	public static final int APP_ID_SHIFT = (64 - APP_ID_BITS);
	public static final long HW1_SWITCH_COOKIE = (long) (HW1_SWITCH_APP_ID & ((1 << APP_ID_BITS) - 1)) << APP_ID_SHIFT;

	// more flow-mod defaults
	protected static final short IDLE_TIMEOUT_DEFAULT = 10;
	protected static final short HARD_TIMEOUT_DEFAULT = 20;

	protected static final short PRIORITY_DEFAULT = 100;
	// Firewall has higher priority than the learning switch flow entries
	protected static final short PRIORITY_FIREWALL = 200;

	// for managing our map sizes
	protected static final int MAX_MACS_PER_SWITCH = 1000;

	// maxinum allowed elephant flow number for one switch
	protected static final int MAX_ELEPHANT_FLOW_NUMBER = 2;

	// maximum allowed destination number for one host
	protected static final int MAX_DESTINATION_NUMBER = 3;

	// maxinum allowed transmission rate
	protected static final int ELEPHANT_FLOW_BAND_WIDTH = 100;

	// time duration the firewall will block each node for 10s
	protected static final int FIREWALL_BLOCK_TIME_DUR = (100 * 1000);

	/**
	 * @param floodlightProvider
	 *            the floodlightProvider to set
	 */
	public void setFloodlightProvider(
			IFloodlightProviderService floodlightProvider) {
		this.floodlightProvider = floodlightProvider;
	}

	@Override
	public String getName() {
		return "hw1switch";
	}

	/**
	 * The method to store the host connected to the server. To record the
	 * amount of elephant flows connected to the server.
	 * 
	 * @param host
	 *            The MAC address of the host
	 * @param server
	 *            The MAC address of the server
	 */
	protected void addToServerToSrcMap(long host, long server) {
		ArrayList<Long> hostlist = serverToSrcMap.get(server);
		if (!hostlist.contains(host))
			hostlist.add(host);
	}

	/**
	 * The method to decide whether the destination MAC is of a server.
	 * 
	 * @param host
	 *            The MAC address of the destination
	 * @return true if the MAC is of one server; false if not.
	 */
	protected boolean isSentToServer(long destMac) {
		String macInString = MACAddress.valueOf(destMac).toString();
		for (int i = 0; i < serverList.size(); i++) {
			if (macInString.equalsIgnoreCase(serverList.get(i)[1]))
				return true;
		}
		return false;

	}

	/**
	 * The method to get a recommended server MAC address.
	 * 
	 * @param match
	 *            The OFMatch structure which contains a server MAC address as
	 *            the destination.
	 * @return the MAC address of the recommended server in order for load
	 *         balance.
	 */
	protected long getLoadBalancedServer(OFMatch match) {
		long destMAC = Ethernet.toLong(match.getDataLayerDestination());
		long tempMAC;
		long newMAC = destMAC;
		int minSize = serverToSrcMap.get(destMAC).size();
		int count;
		for (int i = 0; i < serverList.size(); i++) {
			tempMAC = MACAddress.valueOf(serverList.get(i)[1]).toLong();
			count = serverToSrcMap.get(tempMAC).size();
			if (count < minSize) {
				newMAC = tempMAC;
				minSize = serverToSrcMap.get(tempMAC).size();
			}
		}
		return newMAC;
	}

	/**
	 * The method to retrieve server IP by server MAC.
	 * 
	 * @param mac
	 *            The MAC address of the server
	 * @return The IP address of the server
	 */
	protected int getServerIPByMac(long mac) {
		for (int i = 0; i < serverList.size(); i++) {
			if (serverList.get(i)[1].equalsIgnoreCase(MACAddress.valueOf(mac)
					.toString())) {
				return IPv4.toIPv4Address(serverList.get(i)[0]);
			}
		}
		return 0;
	}

	/**
	 * Adds a elephant flow(srcMac & dstMac) mapping to the switch
	 * 
	 * @param sw
	 *            The switch where the elephant flow is detected
	 * @param macPair
	 *            The srcMac & dstMac pair of the elephant flow
	 */
	protected void addToElephantFlowOnSwitchMap(IOFSwitch sw, String[] macPair) {
		ArrayList<String[]> flowList = this.elephantFlowOnSwitchMap.get(sw);
		if (flowList == null) {
			flowList = new ArrayList<String[]>();
			this.elephantFlowOnSwitchMap.put(sw, flowList);
		}
		if (!flowList.contains(macPair))
			flowList.add(macPair);
	}

	/**
	 * Count the amount of elephant flows on a specific switch
	 * 
	 * @param sw
	 *            The switch on which we want to calculate the elephant flows
	 * @return The amount of elephant flows
	 */
	protected int countElephantFlow(IOFSwitch sw) {
		ArrayList<String[]> flowList = this.elephantFlowOnSwitchMap.get(sw);
		if (flowList == null) {
			return 0;
		}
		return flowList.size();
	}

	/**
	 * Adds a destination to the list mapped by the host MAC
	 * 
	 * @param host
	 *            The MAC address of the host to add
	 * @param dest
	 *            The MAC address of the destination to add
	 */
	protected void addToHostToDestMap(long host, long dest) {
		ArrayList<Long> destlist = this.hostToDestMap.get(host);
		if (destlist == null) {
			destlist = new ArrayList<Long>();
			hostToDestMap.put(host, destlist);
		}
		if (!destlist.contains(new Long(dest)))
			destlist.add(new Long(dest));
	}

	/**
	 * Removes a host and all the destinations from host -> list of destinations
	 * mapping
	 * 
	 * @param host
	 *            The MAC address of the host to remove
	 */
	protected void clearOneHostDestMap(long host) {
		hostToDestMap.remove(host);
	}

	/**
	 * Decide whether the host -> destination mapping exists in the data
	 * structure
	 * 
	 * @param host
	 *            The MAC address of the host
	 * @param dest
	 *            The MAC address of the destination
	 * @return true if exists; false if not
	 */
	protected boolean existInHostToDestMap(long host, long dest) {
		ArrayList<Long> destlist = hostToDestMap.get(host);
		if (destlist != null)
			if (destlist.contains(new Long(dest)))
				return true;
		return false;
	}

	/**
	 * Count the amount of destinations connected to the host
	 * 
	 * @param host
	 *            The MAC address of the host
	 * @return The number of destinations connected to the host
	 */
	protected int countHostConnectedIP(long host) {
		ArrayList<Long> destlist = hostToDestMap.get(host);
		if (destlist != null)
			return destlist.size();
		return 0;
	}

	/**
	 * Adds a host to the MAC->SwitchPort mapping
	 * 
	 * @param sw
	 *            The switch to add the mapping to
	 * @param mac
	 *            The MAC address of the host to add
	 * @param portVal
	 *            The switch port that the host is on
	 */
	protected void addToPortMap(IOFSwitch sw, long mac, short portVal) {
		Map<Long, Short> swMap = macToSwitchPortMap.get(sw);

		if (swMap == null) {
			// May be accessed by REST API so we need to make it thread safe
			swMap = Collections
					.synchronizedMap(new LRULinkedHashMap<Long, Short>(
							MAX_MACS_PER_SWITCH));
			macToSwitchPortMap.put(sw, swMap);
		}

		swMap.put(mac, portVal);
	}

	/**
	 * Removes a host from the MAC->SwitchPort mapping
	 * 
	 * @param sw
	 *            The switch to remove the mapping from
	 * @param mac
	 *            The MAC address of the host to remove
	 */
	protected void removeFromPortMap(IOFSwitch sw, long mac) {
		Map<Long, Short> swMap = macToSwitchPortMap.get(sw);
		if (swMap != null)
			swMap.remove(mac);
	}

	/**
	 * Get the port that a MAC is associated with
	 * 
	 * @param sw
	 *            The switch to get the mapping from
	 * @param mac
	 *            The MAC address to get
	 * @return The port the host is on
	 */
	public Short getFromPortMap(IOFSwitch sw, long mac) {
		Map<Long, Short> swMap = macToSwitchPortMap.get(sw);
		if (swMap != null)
			return swMap.get(mac);
		return null;
	}

	/**
	 * Writes a OFFlowMod to a switch.
	 * 
	 * @param sw
	 *            The switch tow rite the flow_mod to.
	 * @param command
	 *            The FlowMod actions (add, delete, etc).
	 * @param bufferId
	 *            The buffer ID if the switch has buffered the packet.
	 * @param match
	 *            The OFMatch structure to write.
	 * @param outPort
	 *            The switch port to output it to.
	 * @see net.floodlightcontroller.learningswitch.learningswitch.java
	 */
	private void writeFlowMod(IOFSwitch sw, short command, int bufferId,
			OFMatch match, short outPort) {
		OFFlowMod flowMod = (OFFlowMod) floodlightProvider
				.getOFMessageFactory().getMessage(OFType.FLOW_MOD);
		flowMod.setMatch(match);
		flowMod.setCookie(Hw1Switch.HW1_SWITCH_COOKIE);
		flowMod.setCommand(command);
		flowMod.setIdleTimeout(Hw1Switch.IDLE_TIMEOUT_DEFAULT);
		flowMod.setHardTimeout(Hw1Switch.HARD_TIMEOUT_DEFAULT);
		flowMod.setPriority(Hw1Switch.PRIORITY_DEFAULT);
		flowMod.setBufferId(bufferId);
		flowMod.setOutPort((command == OFFlowMod.OFPFC_DELETE) ? outPort
				: OFPort.OFPP_NONE.getValue());
		flowMod.setFlags((command == OFFlowMod.OFPFC_DELETE) ? 0
				: (short) (1 << 0)); // OFPFF_SEND_FLOW_REM

		// set the ofp_action_header/out actions:
		flowMod.setActions(Arrays.asList((OFAction) new OFActionOutput(outPort,
				(short) 0xffff)));
		flowMod.setLength((short) (OFFlowMod.MINIMUM_LENGTH + OFActionOutput.MINIMUM_LENGTH));

		if (log.isTraceEnabled()) {
			log.trace("{} {} flow mod {}",
					new Object[] {
							sw,
							(command == OFFlowMod.OFPFC_DELETE) ? "deleting"
									: "adding", flowMod });
		}

		// and write it out
		try {
			sw.write(flowMod, null);
		} catch (IOException e) {
			log.error("Failed to write {} to switch {}", new Object[] {
					flowMod, sw }, e);
		}
	}

	/**
	 * Writes an OFPacketOut message to a switch.
	 * 
	 * @param sw
	 *            The switch to write the PacketOut to.
	 * @param packetInMessage
	 *            The corresponding PacketIn.
	 * @param egressPort
	 *            The switch port to output the PacketOut.
	 * @see net.floodlightcontroller.learningswitch.learningswitch.java
	 */
	private void writePacketOutForPacketIn(IOFSwitch sw,
			OFPacketIn packetInMessage, short egressPort) {

		OFPacketOut packetOutMessage = (OFPacketOut) floodlightProvider
				.getOFMessageFactory().getMessage(OFType.PACKET_OUT);
		short packetOutLength = (short) OFPacketOut.MINIMUM_LENGTH; // starting
																	// length

		// Set buffer_id, in_port, actions_len
		packetOutMessage.setBufferId(packetInMessage.getBufferId());
		packetOutMessage.setInPort(packetInMessage.getInPort());
		packetOutMessage
				.setActionsLength((short) OFActionOutput.MINIMUM_LENGTH);
		packetOutLength += OFActionOutput.MINIMUM_LENGTH;

		// set actions
		List<OFAction> actions = new ArrayList<OFAction>(1);
		actions.add(new OFActionOutput(egressPort, (short) 0));
		packetOutMessage.setActions(actions);

		// set data - only if buffer_id == -1
		if (packetInMessage.getBufferId() == OFPacketOut.BUFFER_ID_NONE) {
			byte[] packetData = packetInMessage.getPacketData();
			packetOutMessage.setPacketData(packetData);
			packetOutLength += (short) packetData.length;
		}

		// finally, set the total length
		packetOutMessage.setLength(packetOutLength);

		// and write it out
		try {
			sw.write(packetOutMessage, null);
		} catch (IOException e) {
			log.error("Failed to write {} to switch {}: {}", new Object[] {
					packetOutMessage, sw, e });
		}
	}

	/**
	 * Block the host. The method consists of two parts: delete existing flow
	 * entries relevant to the host. And write a fire-wall flow entry which has
	 * a high priority, to drop all the requests from the host.
	 * 
	 * @param sw
	 *            The switch to inform.
	 * @param match
	 *            The OFMatch structure which contains the MAC address of the
	 *            to-be-blocked host.
	 * @param blocktime
	 *            The amount of time that the host should be block.
	 *            (millisecond)
	 */
	private void blockHost(IOFSwitch sw, OFMatch match, long blocktime) {
		/*
		 * Delete all the existing flow entries with the source of host MAC
		 * Address
		 */
		OFMatch matchToDelete = new OFMatch();
		// delete the flow entries with the same source MAC as that of the host.
		matchToDelete.setDataLayerSource(match.getDataLayerSource());
		// Only source MAC is matched.
		matchToDelete.setWildcards(OFMatch.OFPFW_ALL - OFMatch.OFPFW_DL_SRC);

		this.writeFlowMod(sw, OFFlowMod.OFPFC_DELETE, -1, matchToDelete,
				OFPort.OFPP_NONE.getValue());

		// Once the host is blocked, the host-destination mapping of it should
		// be initialized to empty.
		// Thus after blocking, its connection will not encounter problem
		this.clearOneHostDestMap(Ethernet.toLong(match.getDataLayerSource()));

		/*
		 * Create a firewall flow entry to drop all the packets from the host
		 */
		// Action list set to empty. So that no modification nor forwarding will
		// be performed. (Blocked)
		List<OFAction> actionList = new ArrayList<OFAction>();
		OFFlowMod ofmToBlock = (OFFlowMod) floodlightProvider
				.getOFMessageFactory().getMessage(OFType.FLOW_MOD);
		// Only the source MAC is matched
		match.setWildcards(OFMatch.OFPFW_ALL - OFMatch.OFPFW_DL_SRC);
		ofmToBlock.setMatch(match);
		ofmToBlock.setActions(actionList);
		ofmToBlock.setBufferId(-1);
		ofmToBlock.setCommand(OFFlowMod.OFPFC_ADD);
		ofmToBlock.setHardTimeout((short) (blocktime / 1000));
		ofmToBlock.setIdleTimeout((short) (blocktime / 1000));
		// Firewall has a higher priority than learning switch flow entries.
		ofmToBlock.setPriority(Hw1Switch.PRIORITY_FIREWALL);
		ofmToBlock.setFlags((short) (1 << 0));
		ofmToBlock.setCookie(Hw1Switch.HW1_SWITCH_COOKIE);
		ofmToBlock.setLength((short) (OFFlowMod.MINIMUM_LENGTH));

		try {
			log.info(
					"Writing a firewall flow entry to block the host.. FlowMod {} written to switch {}",
					new Object[] { ofmToBlock, sw });
			sw.write(ofmToBlock, null);
			sw.flush();
		} catch (IOException e) {
			log.error("Failed to write {} to switch {}", new Object[] {
					ofmToBlock, sw }, e);
		}
	}

	/**
	 * The method to perform load balance. To write forward and backward flow
	 * entries to the switch. The forward flow entry will modify the destination
	 * IP and MAC address to that of another load-balanced server, and output it
	 * to the corresponding port. The backward flow entry will modify the source
	 * IP and MAC address to that of the original server, and output it to the
	 * port oriented to the host.
	 * 
	 * @param sw
	 *            The switch on which load balance is performed.
	 * @param pi
	 *            A Packet_In message which is sent from the switch and need to
	 *            do load balance.
	 * @param match
	 *            A OFMatch object which is retrieved from the Packet_In
	 *            message.
	 */
	private void loadBalance(IOFSwitch sw, OFPacketIn pi, OFMatch match) {
		long newDestMac = getLoadBalancedServer(match);
		Short outPort1 = getFromPortMap(sw, newDestMac);

		OFMatch matchBack = new OFMatch();
		matchBack.setDataLayerDestination(match.getDataLayerSource());
		matchBack.setDataLayerSource(Ethernet.toByteArray(newDestMac));
		Short outPort2 = getFromPortMap(sw,
				Ethernet.toLong(matchBack.getDataLayerDestination()));

		// Construct and write the forward flow entry from host to server.
		match.setWildcards(((Integer) sw
				.getAttribute(IOFSwitch.PROP_FASTWILDCARDS)).intValue()
				& ~OFMatch.OFPFW_IN_PORT
				& ~OFMatch.OFPFW_DL_SRC
				& ~OFMatch.OFPFW_DL_DST);
		List<OFAction> actionList = new ArrayList<OFAction>();
		actionList.add(new OFActionDataLayerDestination(Ethernet
				.toByteArray(newDestMac)));
		actionList.add(new OFActionNetworkLayerDestination(
				getServerIPByMac(newDestMac)));
		actionList.add(new OFActionOutput(outPort1));
		OFFlowMod ofm = new OFFlowMod();
		ofm.setMatch(match);
		ofm.setActions(actionList);
		ofm.setBufferId(pi.getBufferId());
		ofm.setCommand(OFFlowMod.OFPFC_ADD);
		ofm.setHardTimeout(Hw1Switch.HARD_TIMEOUT_DEFAULT);
		ofm.setIdleTimeout(Hw1Switch.IDLE_TIMEOUT_DEFAULT);
		ofm.setPriority(Hw1Switch.PRIORITY_DEFAULT);
		ofm.setFlags((short) (1 << 0));
		ofm.setCookie(Hw1Switch.HW1_SWITCH_COOKIE);
		ofm.setLength((short) (OFFlowMod.MINIMUM_LENGTH
				+ OFActionDataLayerDestination.MINIMUM_LENGTH
				+ OFActionNetworkLayerDestination.MINIMUM_LENGTH + OFActionOutput.MINIMUM_LENGTH));
		try {
			sw.write(ofm, null);
			sw.flush();
		} catch (IOException e) {
			log.error("Failed to write {} to switch {}",
					new Object[] { ofm, sw }, e);
		}

		// Construct and write the backward flow entry from the load_balanced
		// server to host
		matchBack.setWildcards(OFMatch.OFPFW_ALL - OFMatch.OFPFW_DL_SRC
				- OFMatch.OFPFW_DL_DST);
		List<OFAction> actionListBack = new ArrayList<OFAction>();
		actionListBack.add(new OFActionDataLayerSource(match
				.getDataLayerDestination()));
		actionListBack.add(new OFActionNetworkLayerSource(match
				.getNetworkDestination()));
		actionListBack.add(new OFActionOutput(outPort2));
		OFFlowMod ofmBack = new OFFlowMod();
		ofmBack.setMatch(matchBack);
		ofmBack.setActions(actionListBack);
		ofmBack.setBufferId(-1);
		ofmBack.setCommand(OFFlowMod.OFPFC_ADD);
		ofmBack.setHardTimeout(Hw1Switch.HARD_TIMEOUT_DEFAULT);
		ofmBack.setIdleTimeout(Hw1Switch.IDLE_TIMEOUT_DEFAULT);
		ofmBack.setPriority(Hw1Switch.PRIORITY_DEFAULT);
		ofmBack.setFlags((short) (1 << 0));
		// ofm_back.setOutPort(outPort2);
		ofmBack.setCookie(Hw1Switch.HW1_SWITCH_COOKIE);
		ofmBack.setLength((short) (OFFlowMod.MINIMUM_LENGTH
				+ OFActionDataLayerSource.MINIMUM_LENGTH
				+ OFActionNetworkLayerSource.MINIMUM_LENGTH + OFActionOutput.MINIMUM_LENGTH));
		try {
			sw.write(ofmBack, null);
			sw.flush();
		} catch (IOException e) {
			log.error("Failed to write {} to switch {}", new Object[] {
					ofmBack, sw }, e);
		}
	}

	/**
	 * Processes a OFPacketIn message. If the switch has learned the MAC to port
	 * mapping for the pair it will write a FlowMod for. If the mapping has not
	 * been learned the we will flood the packet.
	 * 
	 * @param sw
	 * @param pi
	 * @param cntx
	 * @return
	 */
	private Command processPacketInMessage(IOFSwitch sw, OFPacketIn pi,
			FloodlightContext cntx) {

		// Read in packet data headers by using OFMatch
		OFMatch match = new OFMatch();
		match.loadFromPacket(pi.getPacketData(), pi.getInPort());
		Long sourceMac = Ethernet.toLong(match.getDataLayerSource());
		Long destMac = Ethernet.toLong(match.getDataLayerDestination());
		OFMatch matchFirewall = match.clone();

		/*
		 * Learning switch implemented here Learn the MAC -> port pair. Decide
		 * the outport on the switch to forward the flow
		 */
		// Neglect the MAC address reserved for 802.1D/Q
		if ((destMac & 0xfffffffffff0L) == 0x0180c2000000L) {
			if (log.isTraceEnabled()) {
				log.trace(
						"ignoring packet addressed to 802.1D/Q reserved addr: switch {}  dest MAC {}",
						new Object[] { sw, HexString.toHexString(destMac) });
			}
			return Command.STOP;
		}
		if ((sourceMac & 0x010000000000L) == 0) {
			// If source MAC is a uni-cast address, learn the port for this
			// MAC/VLAN
			this.addToPortMap(sw, sourceMac, pi.getInPort());
		}

		Short outPort = getFromPortMap(sw, destMac);

		/*
		 * Firewall function(a) implemented here: Block the host if it connects
		 * to too many destinations.
		 */
		if (fireWallActivated) {
			if (blacklist.containsKey(sourceMac)) {
				long duration = System.currentTimeMillis()
						- blacklist.get(sourceMac);
				if (duration < Hw1Switch.FIREWALL_BLOCK_TIME_DUR) {
					/*
					 * if the block time is not expired yet. Block the host on
					 * the switch with a new-calculated duration.
					 */
					this.blockHost(sw, matchFirewall, duration);
					return Command.CONTINUE;
				} else {
					/* remove the host from backlist of time expired. */
					blacklist.remove(sourceMac);
				}
			} else if (!existInHostToDestMap(sourceMac, destMac)
					&& destMac != 0xffffffffffffL
					&& (destMac & 0xffff00000000L) != 0x333300000000L) {
				/*
				 * If the host is not in the blacklist, and the destination has
				 * not been visited before, do the following things
				 */
				if (countHostConnectedIP(sourceMac) >= Hw1Switch.MAX_DESTINATION_NUMBER) {
					/*
					 * If the amount of destinations has reached the cutoff,
					 * block the host and add it to the blacklist.
					 */
					this.blockHost(sw, matchFirewall,
							Hw1Switch.FIREWALL_BLOCK_TIME_DUR);
					blacklist.put(sourceMac, System.currentTimeMillis());
					return Command.CONTINUE;
				} else {
					/*
					 * If the amount of destinations is beneath the cutoff, add
					 * this new destination to the Map structure
					 */
					addToHostToDestMap(sourceMac, destMac);
				}
			}
		}

		/*
		 * Load Balance funtion implemented here
		 */
		if (loadBalanceActivated
				&& isSentToServer(destMac)
				&& getFromPortMap(sw, destMac) != null
				&& getLoadBalancedServer(match) != Ethernet.toLong(match
						.getDataLayerDestination())
				&& getFromPortMap(sw, getLoadBalancedServer(match)) != null) {
			loadBalance(sw, pi, match);
			return Command.CONTINUE;
		}

		/*
		 * If the host is not blocked, and is not sent to the server. Forward
		 * the packet to the corresponding port based on what have been learned
		 * by the learning switch.
		 */
		if (outPort == null)
			this.writePacketOutForPacketIn(sw, pi, OFPort.OFPP_FLOOD.getValue());
		else if (outPort == match.getInputPort()) {
			log.trace(
					"ignoring packet that arrived on same port as learned destination:"
							+ " switch {} dest MAC {} port {}", new Object[] {
							sw, HexString.toHexString(destMac), outPort });
		} else {
			match.setWildcards(((Integer) sw
					.getAttribute(IOFSwitch.PROP_FASTWILDCARDS)).intValue()
					& ~OFMatch.OFPFW_IN_PORT
					& ~OFMatch.OFPFW_DL_SRC
					& ~OFMatch.OFPFW_DL_DST);
			this.writeFlowMod(sw, OFFlowMod.OFPFC_ADD, pi.getBufferId(), match,
					outPort);
		}

		return Command.CONTINUE;
	}

	/**
	 * Processes a flow removed message.
	 * 
	 * @param sw
	 *            The switch that sent the flow removed message.
	 * @param flowRemovedMessage
	 *            The flow removed message.
	 * @return Whether to continue processing this message or stop.
	 */
	private Command processFlowRemovedMessage(IOFSwitch sw,
			OFFlowRemoved flowRemovedMessage) {
		if (flowRemovedMessage.getCookie() != Hw1Switch.HW1_SWITCH_COOKIE) {
			return Command.CONTINUE;
		}

		if (flowRemovedMessage.getPriority() != Hw1Switch.PRIORITY_DEFAULT) {
			return Command.CONTINUE;
		}

		// average bandwidth: byte per second
		long bandwidth = flowRemovedMessage.getByteCount()
				/ flowRemovedMessage.getDurationSeconds();

		if (bandwidth <= Hw1Switch.ELEPHANT_FLOW_BAND_WIDTH) {
			return Command.CONTINUE;
		}
		// The bandwidth exceeds the cutoff. It's defined as an elephant flow.
		// It need further analysis.

		// The following process is for load balance.
		// Record this elephant flow if it's sent to one of the server
		if (loadBalanceActivated
				&& isSentToServer(Ethernet.toLong(flowRemovedMessage.getMatch()
						.getDataLayerDestination()))) {
			this.addToServerToSrcMap(Ethernet.toLong(flowRemovedMessage
					.getMatch().getDataLayerSource()), Ethernet
					.toLong(flowRemovedMessage.getMatch()
							.getDataLayerDestination()));
		}

		// The following process is for elephant flow fire_wall
		if (fireWallActivated) {
			String[] macPair = new String[2];
			macPair[0] = MACAddress.valueOf(
					flowRemovedMessage.getMatch().getDataLayerSource())
					.toString();
			macPair[1] = MACAddress.valueOf(
					flowRemovedMessage.getMatch().getDataLayerDestination())
					.toString();
			addToElephantFlowOnSwitchMap(sw, macPair);
			OFMatch elephantFlowMatch = null;
			if (countElephantFlow(sw) > Hw1Switch.MAX_ELEPHANT_FLOW_NUMBER) {
				ArrayList<String[]> flows = this.elephantFlowOnSwitchMap
						.get(sw);
				ArrayList<String> srcMacs = new ArrayList<String>();
				for (int i = 0; i < flows.size(); i++) { // This for loop is
															// used to avoid
															// blocking one host
															// twice at the same
															// time.
					if (!srcMacs.contains(flows.get(i)[0])) {
						srcMacs.add(flows.get(i)[0]);
						elephantFlowMatch = new OFMatch();
						elephantFlowMatch.setDataLayerSource(flows.get(i)[0]);
						this.blockHost(sw, elephantFlowMatch,
								Hw1Switch.FIREWALL_BLOCK_TIME_DUR);
					}
				}
				this.elephantFlowOnSwitchMap.remove(sw);
			}
		}

		return Command.CONTINUE;
	}

	// IOFMessageListener

	@Override
	public Command receive(IOFSwitch sw, OFMessage msg, FloodlightContext cntx) {
		switch (msg.getType()) {
		case PACKET_IN:
			return this.processPacketInMessage(sw, (OFPacketIn) msg, cntx);

		case FLOW_REMOVED:
			return this.processFlowRemovedMessage(sw, (OFFlowRemoved) msg);

		case ERROR:
			log.info("received an error {} from switch {}", (OFError) msg, sw);
			return Command.CONTINUE;
		default:
			break;
		}
		log.error("received an unexpected message {} from switch {}", msg, sw);
		return Command.CONTINUE;
	}

	@Override
	public boolean isCallbackOrderingPrereq(OFType type, String name) {
		return false;
	}

	@Override
	public boolean isCallbackOrderingPostreq(OFType type, String name) {
		return false;
	}

	// IFloodlightModule

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleServices() {
		Collection<Class<? extends IFloodlightService>> l = new ArrayList<Class<? extends IFloodlightService>>();
		return l;
	}

	@Override
	public Map<Class<? extends IFloodlightService>, IFloodlightService> getServiceImpls() {
		Map<Class<? extends IFloodlightService>, IFloodlightService> m = new HashMap<Class<? extends IFloodlightService>, IFloodlightService>();
		return m;
	}

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleDependencies() {
		Collection<Class<? extends IFloodlightService>> l = new ArrayList<Class<? extends IFloodlightService>>();
		l.add(IFloodlightProviderService.class);
		return l;
	}

	@Override
	public void init(FloodlightModuleContext context)
			throws FloodlightModuleException {

		floodlightProvider = context
				.getServiceImpl(IFloodlightProviderService.class);
		macToSwitchPortMap = new ConcurrentHashMap<IOFSwitch, Map<Long, Short>>();
		hostToDestMap = new ConcurrentHashMap<Long, ArrayList<Long>>();
		blacklist = new ConcurrentHashMap<Long, Long>();
		elephantFlowOnSwitchMap = new ConcurrentHashMap<IOFSwitch, ArrayList<String[]>>();
		serverToSrcMap = new ConcurrentHashMap<Long, ArrayList<Long>>();
		for (int i = 0; i < serverList.size(); i++) {
			serverToSrcMap.put(MACAddress.valueOf(serverList.get(i)[1])
					.toLong(), new ArrayList<Long>());
		}

	}

	@Override
	public void startUp(FloodlightModuleContext context) {
		floodlightProvider.addOFMessageListener(OFType.PACKET_IN, this);
		floodlightProvider.addOFMessageListener(OFType.FLOW_REMOVED, this);
		floodlightProvider.addOFMessageListener(OFType.ERROR, this);
	}
}