# 
# Copyright (C) 2008 OpenWrt.org
#

include $(TOPDIR)/rules.mk

PKG_NAME:=nmap-scan
PKG_RELEASE:=1

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)

include $(INCLUDE_DIR)/package.mk

define Package/nmap-scan
	SECTION:=utils
	CATEGORY:=Network
	TITLE:=Scan host service by nmap.
endef


define Package/nmap-scan/description
	It is used for scan host service.
endef

define Package/nmap-scan/config
	select PACKAGE_nmap
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) -fr ./src/* $(PKG_BUILD_DIR)
endef

define Package/nmap-scan/install
	install -d -m0755 $(1)/usr/sbin
	install -d -m0755 $(1)/etc/init.d
	install -m0755 $(PKG_BUILD_DIR)/nmap-scan $(1)/usr/sbin/
	install -m0755 ./files/nmap-scan.init $(1)/etc/init.d
endef

$(eval $(call BuildPackage,nmap-scan))
