// SPDX-License-Identifier: MIT
pragma solidity ^0.8.10;

import "@openzeppelin/contracts-upgradeable/security/PausableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts-upgradeable/utils/cryptography/draft-EIP712Upgradeable.sol";
import "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";
import "@openzeppelin/contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol";
import "./IRoles.sol";

interface IRoyalties {
    function royaltyInfo(uint256 tokenId, uint256 value) external returns(address receiver, uint256 royaltyAmount);
}

interface INft {
    function safeMint(address _to, string memory _uri, address _creator) external;
}

contract MisteryBoxCollector is Initializable, PausableUpgradeable, UUPSUpgradeable, EIP712Upgradeable, ReentrancyGuardUpgradeable {
    // INft nftContract;
    uint256 public fee;

    IRoles public roles;

    struct Nft {
        string _uri;
        address _signer;
        string _timeStamp;
        INft _nftContract;
    }

    mapping(bytes => bool) private isMinted;

    modifier onlyDefaultAdmin {
        require(roles.hasRole(roles.getHashRole("DEFAULT_ADMIN_ROLE"), msg.sender), "Error, the account is not the default admin");
        _;
    }

    event eventMint(string moralisId);

    function initialize(address _rolesContracts) initializer external{
        __ReentrancyGuard_init();
        __EIP712_init("Mystery Box", "1.0.0");
        __UUPSUpgradeable_init();
        roles = IRoles(_rolesContracts);
        fee = 0.005 gwei;
    }
    
    function redeem(
        Nft memory _nftData,
        bytes calldata signature,
        string memory _moralisId
    ) external payable whenNotPaused nonReentrant{
        require(msg.value >= fee, "Insufficient funds");
        
        require(_verify(_nftData._signer, _hash(_nftData._uri, _nftData._signer, address(_nftData._nftContract),
                        _nftData._timeStamp), signature),"Invalid signature");

        require(!isMinted[signature], "This NFT was already minted");

        isMinted[signature] = true;
        _nftData._nftContract.safeMint(msg.sender, _nftData._uri, _nftData._signer);
        roles.addPreSaleWhitelist(msg.sender);


        require(roles.getCollector() != address(0), "Can't send value to the address 0");
        payable(roles.getCollector()).transfer(msg.value);
        emit eventMint(_moralisId);
    }

    function airdropRedeem(
        Nft memory _nftData,
        bytes calldata signature,
        string memory _moralisId
    ) external whenNotPaused nonReentrant{
        require(roles.hasRole(roles.getHashRole("AIRDROP"), msg.sender),"No tenes rol de airdrop pa");
        roles.revokeRole(roles.getHashRole("AIRDROP"), msg.sender);

        require(_verify(_nftData._signer, _hash(_nftData._uri, _nftData._signer, address(_nftData._nftContract),
                        _nftData._timeStamp), signature),"Invalid signature");

        require(!isMinted[signature], "This NFT was already minted");
    
        isMinted[signature] = true;
        _nftData._nftContract.safeMint(msg.sender, _nftData._uri, _nftData._signer);
        emit eventMint(_moralisId);
    }

    function _hash(string memory _uri, address _signer, address _nftContract, string memory _timeStamp)
        internal
        view
        returns (bytes32)
    {
        return
            _hashTypedDataV4(
                keccak256(
                    abi.encode(
                        keccak256("NFT(string _uri,address _signer,address _nftContract,string _timeStamp)"),
                        keccak256(bytes(_uri)),
                        _signer,
                        _nftContract,
                        keccak256(bytes(_timeStamp))
                    )
                )
            );
    }

    function _verify(
        address signer,
        bytes32 digest,
        bytes memory signature
    ) internal view returns (bool) {
        return SignatureChecker.isValidSignatureNow(signer, digest, signature);
    }
    
    function setFee(uint256 _newFee) external {
        require(roles.hasRole(roles.getHashRole("NFT_ADMIN_ROLE"), msg.sender), "Error, the admin does not have an admin role"); 
        fee = _newFee * (1 gwei);
    }

    function pause() external onlyDefaultAdmin {
        //Debería ser la misma persona la que deploya el contrato de roles y el de misteryBox
        _pause();
    }
    
    function unpause() external onlyDefaultAdmin {
        //Debería ser la misma persona la que deploya el contrato de roles y el de misteryBox
        _unpause();
    }

    function _authorizeUpgrade(address newImplementation)
        internal
        whenPaused()
        override
    {}

    function upgradeTo(address newImplementation) external override onlyDefaultAdmin whenPaused {
         _authorizeUpgrade(newImplementation);
        _upgradeToAndCallUUPS(newImplementation, new bytes(0), false);
       
    }

    function upgradeToAndCall(address newImplementation, bytes memory data) external payable override onlyDefaultAdmin whenPaused {
          _authorizeUpgrade(newImplementation);
        _upgradeToAndCallUUPS(newImplementation, data, true);
      
    }

} 