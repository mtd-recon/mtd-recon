from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.net import Mininet
from mininet.topo import Topo
from mininet.node import RemoteController, OVSSwitch

class SimpleTopo( Topo ):

    def build( self ):

        h1 = self.addHost( 'h1' )
        h2 = self.addHost( 'h2' )
        h3 = self.addHost( 'h3' )
        h4 = self.addHost( 'h4' )
        s1 = self.addSwitch( 's1' )

        self.addLink( s1, h1 )
        self.addLink( s1, h2 )
        self.addLink( s1, h3 )
        self.addLink( s1, h4 )

def runSimpleTopo():
    

    # Create an instance of our topology
    topo = SimpleTopo()

    # Create a network based on the topology using OVS and controlled by
    # a remote controller.
    net = Mininet(
        topo=topo,
        controller=lambda name: RemoteController( name, ip='127.0.0.1' ),
        switch=OVSSwitch,
        autoSetMacs=True )

    # Add NAT connectivity
    net.addNAT().configDefault()

    # Actually start the network
    net.start()

    # Drop the user in to a CLI so user can run commands.
    CLI( net )

    # After the user exits the CLI, shutdown the network.
    net.stop()

if __name__ == '__main__':
    # This runs if this file is executed directly
    setLogLevel( 'info' )
    runSimpleTopo()

# Allows the file to be imported using `mn --custom <filename> --topo minimal`
topos = {
    'simple': SimpleTopo
}