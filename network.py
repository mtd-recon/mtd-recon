from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.net import Mininet
from mininet.topo import Topo
from mininet.node import RemoteController, OVSSwitch
from mininet.nodelib import NAT



class MinimalTopo( Topo ):
    "Minimal topology with a single switch and two hosts"

    def build( self ):

        natIP= '10.0.0.254'

        # Create two hosts.
        h1 = self.addHost( 'h1', ip="fe80::200:ff:fe00:1/64")
        h2 = self.addHost( 'h2', ip="fe80::200:ff:fe00:2/64")
        h3 = self.addHost( 'h3', ip="fe80::200:ff:fe00:3/64")
        h4 = self.addHost( 'h4', ip="fe80::200:ff:fe00:4/64")
        h5 = self.addHost( 'h5', ip="fe80::200:ff:fe00:5/64")
        h6 = self.addHost( 'h6', ip="fe80::200:ff:fe00:6/64")
        

        info(self.hosts)

        # Create a switch
        s1 = self.addSwitch( 's1' , protocols='OpenFlow13')

        # Add links between the switch and each host
        self.addLink( s1, h1 )
        self.addLink( s1, h2 )
        self.addLink( s1, h3 )
        self.addLink( s1, h4 )
        self.addLink( s1, h5 )
        self.addLink( s1, h6 )

def runMinimalTopo():
    "Bootstrap a Mininet network using the Minimal Topology"

    # Create an instance of our topology
    topo = MinimalTopo()

    # Create a network based on the topology using OVS and controlled by
    # a remote controller.
    net = Mininet(
        topo=topo,
        controller=lambda name: RemoteController( name, ip='127.0.0.1', version='OpenFlow13'),
        switch=OVSSwitch, 
        autoSetMacs=True)

    # Add NAT connectivity
    #net.addNAT(ip='10.0.0.254', dns='8.8.8.8', connect=True).configDefault()
    #net.addNAT().configDefault()

    # Actually start the network
    net.start()

    # WARNING: This command also runs on the local device and all therefore also on all the other nodes:
    # Note that only the network is virtualized; each host process sees the same set of processes and directories.
    # It would be possible to use separate process spaces with Linux containers, but currently Mininet doesn’t do that. Having everything run 
    # in the “root” process namespace is convenient for debugging, because it allows you to see all of the processes from the console using ps, kill, etc. (http://mininet.org/walkthrough/#interact-with-hosts-and-switches)
    # Therefore only different network namespaces are used, but not the PID, user or mount namespace stays the same
    #h1 = net.get('h1')
    #h1.cmd('grep -qxF "nameserver 192.168.1.84" /etc/resolv.conf || echo "nameserver 192.168.1.84" >> /etc/resolv.conf')

    info( "*** Hosts are running and should have internet connectivity\n" )
    info( "*** Type 'exit' or control-D to shut down network\n" )

    # Drop the user in to a CLI so user can run commands.
    CLI( net )


    #cleanup
    #h1.cmd('sudo sed -i "/nameserver 192.168.1.84/d" /etc/resolv.conf')
    
    # After the user exits the CLI, shutdown the network.
    net.stop()

if __name__ == '__main__':
    # This runs if this file is executed directly
    setLogLevel( 'info' )
    runMinimalTopo()

# Allows the file to be imported using `mn --custom <filename> --topo minimal`
topos = {
    'minimal': MinimalTopo
}
