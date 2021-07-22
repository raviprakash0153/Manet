#include "ns3/core-module.h"
#include "ns3/config-store-module.h"
#include "ns3/mobility-module.h"
#include "ns3/wifi-module.h"
#include "ns3/aodv-module.h"
#include "ns3/netanim-module.h"
#include "ns3/internet-module.h"
#include "ns3/position-allocator.h"
#include "ns3/applications-module.h"
#include "ns3/network-module.h"
#include "ns3/flow-monitor-module.h"
#include "ns3/pointer.h"
#include "myapp.h"
#include <iostream>
#include <stdlib.h>
#include <stdio.h>
#include <fstream>
#include <vector>
#include <string>

using namespace ns3;

/*******************************************************************************
			Enable log for this program
********************************************************************************/

NS_LOG_COMPONENT_DEFINE ("SimpleAdhoc");

/*******************************************************************************
			Main Function
********************************************************************************/
int main(int argc, char *argv[])

{
Time::SetResolution (Time::NS);

 int Number_of_Node=10;
 CommandLine cmd;
 cmd.AddValue("Number_of_Node", "Total Nodes", Number_of_Node);
 cmd.Parse (argc, argv);


 
  std::string phyMode ("DsssRate1Mbps");
  
 NodeContainer wifiNodeContainer;
 NodeContainer not_malicious;
 NodeContainer malicious;		
 wifiNodeContainer.Create (Number_of_Node);
 not_malicious.Add(wifiNodeContainer.Get(0));
 not_malicious.Add(wifiNodeContainer.Get(7));
 not_malicious.Add(wifiNodeContainer.Get(3));
 not_malicious.Add(wifiNodeContainer.Get(5));
 not_malicious.Add(wifiNodeContainer.Get(6));
 not_malicious.Add(wifiNodeContainer.Get(8));
 not_malicious.Add(wifiNodeContainer.Get(9));
 not_malicious.Add(wifiNodeContainer.Get(1));
 malicious.Add(wifiNodeContainer.Get(2));
 malicious.Add(wifiNodeContainer.Get(4));


//Set Non-unicastMode rate to unicast mode
  Config::SetDefault ("ns3::WifiRemoteStationManager::NonUnicastMode",StringValue (phyMode));


WifiHelper wifi;
wifi.SetStandard (WIFI_PHY_STANDARD_80211b);

WifiMacHelper wifiMac;
wifiMac.SetType ("ns3::AdhocWifiMac");

wifi.SetRemoteStationManager( "ns3::ConstantRateWifiManager",
                                "DataMode", StringValue (phyMode),
                                "ControlMode", StringValue (phyMode));

  YansWifiPhyHelper wifiPhy = YansWifiPhyHelper::Default ();
  YansWifiChannelHelper wifiChannel;
  wifiChannel.SetPropagationDelay ("ns3::ConstantSpeedPropagationDelayModel");
  wifiChannel.AddPropagationLoss ("ns3::LogDistancePropagationLossModel",
					"Exponent", DoubleValue (3.0),
					"ReferenceLoss", DoubleValue (40.0459));
  wifiPhy.SetChannel (wifiChannel.Create ());

  
  
NetDeviceContainer adhocDevices = wifi.Install (wifiPhy, wifiMac, wifiNodeContainer);

  MobilityHelper mobilityAdhoc;
  int64_t streamIndex = 0; // used to get consistent mobility across scenarios

  ObjectFactory pos;
  pos.SetTypeId ("ns3::RandomRectanglePositionAllocator");
  pos.Set ("X", StringValue ("ns3::UniformRandomVariable[Min=0.0|Max=500.0]"));
  pos.Set ("Y", StringValue ("ns3::UniformRandomVariable[Min=0.0|Max=500.0]"));

  Ptr<PositionAllocator> taPositionAlloc = pos.Create ()->GetObject<PositionAllocator> ();
  streamIndex += taPositionAlloc->AssignStreams (streamIndex);

  mobilityAdhoc.SetMobilityModel ("ns3::RandomWaypointMobilityModel",
                                 "Speed", StringValue ("ns3::UniformRandomVariable[Min=0.10|Max=10.0]"),
				 "Pause", StringValue ("ns3::ConstantRandomVariable[Constant=2.0]"),
                                 "PositionAllocator", PointerValue (taPositionAlloc));
  mobilityAdhoc.SetPositionAllocator (taPositionAlloc);
  mobilityAdhoc.Install (wifiNodeContainer);
  streamIndex += mobilityAdhoc.AssignStreams (wifiNodeContainer, streamIndex);


AodvHelper aodv;
AodvHelper malicious_aodv;
InternetStackHelper stack;
stack.SetRoutingHelper (aodv);
stack.Install (not_malicious);
  
  malicious_aodv.Set("IsMalicious",BooleanValue(true)); // putting *false* instead of *true* would disable the malicious behavior of the node
  stack.SetRoutingHelper (malicious_aodv);
  stack.Install (malicious);
Ipv4AddressHelper address;
address.SetBase ("10.1.1.0", "255.255.255.0");



Ipv4InterfaceContainer interfaces;
interfaces = address.Assign (adhocDevices);

	
 ApplicationContainer cbrApps;
  uint16_t cbrPort = 12345;
  // flow 1:  node 0 -> node 7
  OnOffHelper onOffHelper1 ("ns3::UdpSocketFactory", InetSocketAddress (Ipv4Address ("10.1.1.8"), cbrPort));
  onOffHelper1.SetAttribute ("PacketSize", UintegerValue (1024));
  onOffHelper1.SetAttribute ("OnTime",  StringValue ("ns3::ConstantRandomVariable[Constant=1.0]"));
  onOffHelper1.SetAttribute ("OffTime", StringValue ("ns3::ConstantRandomVariable[Constant=0.0]"));
  onOffHelper1.SetAttribute ("DataRate", StringValue ("2048bps"));
  onOffHelper1.SetAttribute ("StartTime", TimeValue (Seconds (100.00)));
  onOffHelper1.SetAttribute ("StopTime", TimeValue (Seconds (250.00)));
  cbrApps.Add (onOffHelper1.Install (wifiNodeContainer.Get (0)));  
 
AnimationInterface anim ("aodv.xml");

//wifiPhy.EnablePcapAll ("aodv");

FlowMonitorHelper flowmonHelper;
Ptr<FlowMonitor> flowmon = flowmonHelper.InstallAll ();
Simulator::Stop (Seconds (300));		
Simulator::Run ();

flowmon->SerializeToXmlFile ("aodv.flowmon", true, true);

/*************************************************************************************************************
	to calculate the output for some parameters and display in terminal 
*************************************************************************************************************/

Ptr<Ipv4FlowClassifier> classifier = DynamicCast<Ipv4FlowClassifier> (flowmonHelper.GetClassifier ());
std::map<FlowId, FlowMonitor::FlowStats> stats = flowmon->GetFlowStats ();
for (std::map<FlowId, FlowMonitor::FlowStats>::const_iterator iter = stats.begin (); iter != stats.end (); ++iter)
    {
	  Ipv4FlowClassifier::FiveTuple t = classifier->FindFlow (iter->first);

if ((t.sourceAddress == Ipv4Address("10.1.1.1") && t.destinationAddress == Ipv4Address("10.1.1.8")))          
        {
          
	  NS_LOG_UNCOND("\nFlow ID: " << iter->first << " Src Addr " << t.sourceAddress << " Dst Addr " << t.destinationAddress);
	  NS_LOG_UNCOND("Total transmit Packets = "<<iter->second.txPackets);
          NS_LOG_UNCOND("Total Receive Packets = "<<iter->second.rxPackets);	
	  NS_LOG_UNCOND("Mean Delay (sec) = " << iter->second.delaySum.GetSeconds() / iter->second.rxPackets);
          NS_LOG_UNCOND("PDR = " << iter->second.rxPackets * 100 / iter->second.txPackets <<" %");
    	  NS_LOG_UNCOND("Throughput (Kibps): " << iter->second.rxBytes * 8.0 / (iter->second.timeLastRxPacket.GetSeconds()-iter->second.timeFirstTxPacket.GetSeconds()) / 1024  << " Kibps" <<"\n");
     	 }
}

Simulator::Destroy ();	
return 0;
}



