run-arp:
	mvn clean install -DSkipTests
	onos-app localhost install! ~/final-project/apps/proxyarp/target/proxyarp-1.0-SNAPSHOT.oar

rerun-arp:
	onos-app localhost deactivate nycu.sdnnfv.proxyarp
	onos-app localhost uninstall nycu.sdnnfv.proxyarp
	mvn clean install -DSkipTests
	onos-app localhost install! ~/final-project/apps/proxyarp/target/proxyarp-1.0-SNAPSHOT.oar