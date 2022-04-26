// SPDX-License-Identifier: MIT
pragma solidity ^0.8.10;

import "@openzeppelin/contracts-upgradeable/token/ERC721/extensions/ERC721URIStorageUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/CountersUpgradeable.sol";
//import "@openzeppelin/contracts-upgradeable/interfaces/IERC721ReceiverUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/security/PausableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/token/common/ERC2981Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol";
import "./IRoles.sol";


contract ArtNft is Initializable, UUPSUpgradeable, ERC721URIStorageUpgradeable, ERC2981Upgradeable, PausableUpgradeable, ReentrancyGuardUpgradeable {
    using CountersUpgradeable for CountersUpgradeable.Counter;

    CountersUpgradeable.Counter private _tokenIdCounter;

    IRoles roles;

    string public contractURI;

    uint96 public royaltyFee;

    uint public maxNftsPerWallet; // Es 1 para poder testear el contrato

    mapping(bytes => bool) private isMinted;

    event eventMint(
        address indexed minterAddress,
        uint tokenId,
        string description
    );

    modifier onlyDefaultAdmin {
        require(roles.hasRole(roles.getHashRole("DEFAULT_ADMIN_ROLE"), msg.sender), "Error, the account is not the default admin");
        _;
    }

    modifier onlyFactory {
        require(roles.hasRole(roles.getHashRole("FACTORY_ADDRESS"), msg.sender), "Error, the account is not the factory contract");
        _;
    }

    function initialize(
        string memory _name,
        string memory _symbol,
        string memory _contractUri,
        address _rolesContract
        ) initializer external{
        require(_rolesContract != address(0));
        __ReentrancyGuard_init();
        __ERC721_init(_name, _symbol);
        __UUPSUpgradeable_init();
        __ERC2981_init();
        __ERC721URIStorage_init();
        __Pausable_init();
        roles = IRoles(_rolesContract);
        contractURI = _contractUri;
        royaltyFee = 2000;
        maxNftsPerWallet = 1;
        }

    function supportsInterface(bytes4 interfaceId)
        public
        view
        virtual
        override(ERC721Upgradeable, ERC2981Upgradeable)
        returns (bool)
    {
        return super.supportsInterface(interfaceId);
    }

    /**
     * @dev See {ERC721/ERC721-_safeMint}.
     */
    function safeMint(
        address _to,
        string memory _uri,
        address _creator
    ) external whenNotPaused nonReentrant{
        require(balanceOf(_to) < maxNftsPerWallet, "Can't mint more nfts in this wallet");
        //Crear el rol antes de llamar a esta función
        require(roles.hasRole(roles.getHashRole("MISTERY_BOX_ADDRESS"), msg.sender), "Only mistery box contract can call redeem");
        
        uint256 tokenId = _tokenIdCounter.current();
        _tokenIdCounter.increment();
        _safeMint(_to, tokenId);
        _setTokenURI(tokenId, _uri);
        _setTokenRoyalty(tokenId, _creator, royaltyFee);
        emit eventMint(_to, tokenId, "Mint new NFT");
    }

    function setMaxNftsPerWallet(uint _max) external whenNotPaused(){
        require(roles.hasRole(roles.getHashRole("NFT_ADMIN_ROLE"), msg.sender), "The address doesn't have admin role"); 
        maxNftsPerWallet = _max;
    }

    function setRoyaltyFee(uint96 _fee) external whenNotPaused(){
        require(_fee <= _feeDenominator(), "ERC2981: royalty fee will exceed salePrice");
        royaltyFee = _fee;
    }

    function pause() external onlyDefaultAdmin {
        //Debería ser la misma persona la que deploya el contrato de roles y el de misteryBox
        _pause();
    }

    function unpause() external onlyDefaultAdmin {
        //Debería ser la misma persona la que deploya el contrato de roles y el de misteryBox
        _unpause();
    }

    function _beforeTokenTransfer(
        address from,
        address to,
        uint256 tokenId
    ) internal virtual override{
        require(!paused(), "ERC721Pausable: token transfer while paused");
        require(balanceOf(to) < maxNftsPerWallet, "Can't send more nfts to this wallet"); //preg    
        require(address(0) != to, "Can't transfer to the address 0");
        super._beforeTokenTransfer(from, to, tokenId);
    }

    function _authorizeUpgrade(address newImplementation)
        internal
        override
        onlyDefaultAdmin
        whenPaused()
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
