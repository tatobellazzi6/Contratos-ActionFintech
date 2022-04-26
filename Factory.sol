// SPDX-License-Identifier: MIT

pragma solidity ^0.8.10;

import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "./ArtNft.sol";
import "./IRoles.sol";

contract CollectionFactoryUUPS is ReentrancyGuard{
    address immutable collectionImplementation;

    IRoles roles;

    event CollectionDeployed(address collectionAddress);

    constructor(address _rolesContract, address _implementation) {
        require(_rolesContract != address(0) && _implementation != address(0));
        collectionImplementation = _implementation;
        roles = IRoles(_rolesContract);
    }

    function createCollection(string calldata _name, string calldata _symbol, string calldata _contractUri) external nonReentrant returns (address) {
        require(roles.hasRole(roles.getHashRole("NFT_ADMIN_ROLE"), msg.sender), "The address doesn't have admin role"); 

        ERC1967Proxy proxy = new ERC1967Proxy(
            collectionImplementation,
            abi.encodeWithSelector(ArtNft(address(0)).initialize.selector, _name, _symbol, _contractUri, address(roles))
        );
        emit CollectionDeployed(address(proxy));
        return address(proxy);
    }
}