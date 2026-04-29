// SPDX-License-Identifier: GPL-3.0
/*
    Copyright 2021 0KIMS association.

    This file is generated with [snarkJS](https://github.com/iden3/snarkjs).

    snarkJS is a free software: you can redistribute it and/or modify it
    under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    snarkJS is distributed in the hope that it will be useful, but WITHOUT
    ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
    or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public
    License for more details.

    You should have received a copy of the GNU General Public License
    along with snarkJS. If not, see <https://www.gnu.org/licenses/>.
*/

pragma solidity >=0.7.0 <0.9.0;

contract Verifier_AnonNullifierKycTransferLockedBatch {
    // Scalar field size
    uint256 constant r    = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
    // Base field size
    uint256 constant q   = 21888242871839275222246405745257275088696311157297823662689037894645226208583;

    // Verification Key data
    uint256 constant alphax  = 20491192805390485299153009773594534940189261866228447918068658471970481763042;
    uint256 constant alphay  = 9383485363053290200918347156157836566562967994039712273449902621266178545958;
    uint256 constant betax1  = 4252822878758300859123897981450591353533073413197771768651442665752259397132;
    uint256 constant betax2  = 6375614351688725206403948262868962793625744043794305715222011528459656738731;
    uint256 constant betay1  = 21847035105528745403288232691147584728191162732299865338377159692350059136679;
    uint256 constant betay2  = 10505242626370262277552901082094356697409835680220590971873171140371331206856;
    uint256 constant gammax1 = 11559732032986387107991004021392285783925812861821192530917403151452391805634;
    uint256 constant gammax2 = 10857046999023057135944570762232829481370756359578518086990519993285655852781;
    uint256 constant gammay1 = 4082367875863433681332203403145435568316851327593401208105741076214120093531;
    uint256 constant gammay2 = 8495653923123431417604973247489272438418190587263600148770280649306958101930;
    uint256 constant deltax1 = 11559732032986387107991004021392285783925812861821192530917403151452391805634;
    uint256 constant deltax2 = 10857046999023057135944570762232829481370756359578518086990519993285655852781;
    uint256 constant deltay1 = 4082367875863433681332203403145435568316851327593401208105741076214120093531;
    uint256 constant deltay2 = 8495653923123431417604973247489272438418190587263600148770280649306958101930;

    
    uint256 constant IC0x = 3109639421564853791155842380200901781361441692478860462397265586846921632403;
    uint256 constant IC0y = 14602683075995116425607452449450126857764185144843351744984238917030659398344;
    
    uint256 constant IC1x = 4757236139029444951172138664786717186530949221747239770959958392147617992413;
    uint256 constant IC1y = 8597050350247852011654764687468024484851434937349651787789519711504908115216;
    
    uint256 constant IC2x = 12948452582467101747528019364297083092800854196745118031017319348890467446634;
    uint256 constant IC2y = 20069144719740321670183156836805162829146052481642781067019156124525654767552;
    
    uint256 constant IC3x = 5682849691284349419400024489196910525163170701430108493867212919258499336367;
    uint256 constant IC3y = 19004139386219844139100765155762385230299317245182890319092038491875207157099;
    
    uint256 constant IC4x = 16561613752924642840749932727799954827864096258897068863152854378910809882073;
    uint256 constant IC4y = 10078128027680398379776777223791012102064087051042295027800711843877906268527;
    
    uint256 constant IC5x = 8182130881151122451646645597949908299365149269305024949913099553404486716141;
    uint256 constant IC5y = 6145161223100257771411959622004999605309670358068736501415042893430238154647;
    
    uint256 constant IC6x = 12383287711941795352252977015799710523115530570511030521090481116412423417147;
    uint256 constant IC6y = 3649378366326563990647522424351481978348743661081528754445602149747307058934;
    
    uint256 constant IC7x = 13011409203146709135368744912529536844461033607799961227886030386747961572435;
    uint256 constant IC7y = 7520140946534503662149502921594644444367860791164673143522299978155901898396;
    
    uint256 constant IC8x = 13219653999243590051384175499639011634567193244747350005815040435364463320350;
    uint256 constant IC8y = 10203729312193045351677171756656478768623336540375390418010922522683702659576;
    
    uint256 constant IC9x = 10277351290658576763490450225017950891855665414046219722057251582622972677509;
    uint256 constant IC9y = 11061283750416159645461813986104946682190494731009041729906750004132262644906;
    
    uint256 constant IC10x = 6079351855012497895940299512483763394242253620429422661560419541923233556115;
    uint256 constant IC10y = 6680143936846354304930195894341997578922674005659750046184063775464314118988;
    
    uint256 constant IC11x = 4646497769986346300238389141754867439196143343745289421396159193831259985086;
    uint256 constant IC11y = 16092361711047028330689277247188326818862128430229885304693699890811102072124;
    
    uint256 constant IC12x = 14981820049717906787140801630855082026037894166649975292907477686337379406099;
    uint256 constant IC12y = 10023954357670398983419336174732381839286842935656421907077224319374056331459;
    
    uint256 constant IC13x = 6861771372452031397774366130947514616615507031151772303454530679630942509265;
    uint256 constant IC13y = 10710603522689233751937848772270647909063950178475429169949386895841175164676;
    
    uint256 constant IC14x = 17377321778555306835353780119736294709925811418954770175820314042472369987130;
    uint256 constant IC14y = 5418092792734427711595263286206603563992403888659693891253133209008852173508;
    
    uint256 constant IC15x = 741585891765174035206037809260679013575085591577483774520926009934382611714;
    uint256 constant IC15y = 3876556080398388529423533467247035011961172901966793272635969602295112322922;
    
    uint256 constant IC16x = 18625911668319979994726849394616479500189454778942219240761547956563212747660;
    uint256 constant IC16y = 21840855535405180919167019558139040995922042177947482979245025167135987187004;
    
    uint256 constant IC17x = 18545657312827579937032131521472682651589731017098203936372342168150929460849;
    uint256 constant IC17y = 21147743863269889380802064720607755747467305600567707216017762863564338616885;
    
    uint256 constant IC18x = 4091197068874257137040156138483101954458182755946719424828746452717284893929;
    uint256 constant IC18y = 9223959413498656361969627996780816291222314145666565643223287948957377112397;
    
    uint256 constant IC19x = 13031473206848109156009799818470446117761053545363309037989631776853508955196;
    uint256 constant IC19y = 4401162445385882157865742248534761827427723671111517589342205503610048251881;
    
    uint256 constant IC20x = 1885679620492986566202291122663198145951947622895679245093425720849515087023;
    uint256 constant IC20y = 21388080445163443172746453788370521608143097357987045041200715681769454521138;
    
    uint256 constant IC21x = 16641312849311902729283252847268728670708501448545623503256438694217382243449;
    uint256 constant IC21y = 18490387447983139170161805991247406185458277186507409040927048237613862133743;
    
 
    // Memory data
    uint16 constant pVk = 0;
    uint16 constant pPairing = 128;

    uint16 constant pLastMem = 896;

    function verifyProof(uint[2] calldata _pA, uint[2][2] calldata _pB, uint[2] calldata _pC, uint[21] calldata _pubSignals) public view returns (bool) {
        assembly {
            function checkField(v) {
                if iszero(lt(v, r)) {
                    mstore(0, 0)
                    return(0, 0x20)
                }
            }
            
            // G1 function to multiply a G1 value(x,y) to value in an address
            function g1_mulAccC(pR, x, y, s) {
                let success
                let mIn := mload(0x40)
                mstore(mIn, x)
                mstore(add(mIn, 32), y)
                mstore(add(mIn, 64), s)

                success := staticcall(sub(gas(), 2000), 7, mIn, 96, mIn, 64)

                if iszero(success) {
                    mstore(0, 0)
                    return(0, 0x20)
                }

                mstore(add(mIn, 64), mload(pR))
                mstore(add(mIn, 96), mload(add(pR, 32)))

                success := staticcall(sub(gas(), 2000), 6, mIn, 128, pR, 64)

                if iszero(success) {
                    mstore(0, 0)
                    return(0, 0x20)
                }
            }

            function checkPairing(pA, pB, pC, pubSignals, pMem) -> isOk {
                let _pPairing := add(pMem, pPairing)
                let _pVk := add(pMem, pVk)

                mstore(_pVk, IC0x)
                mstore(add(_pVk, 32), IC0y)

                // Compute the linear combination vk_x
                
                g1_mulAccC(_pVk, IC1x, IC1y, calldataload(add(pubSignals, 0)))
                
                g1_mulAccC(_pVk, IC2x, IC2y, calldataload(add(pubSignals, 32)))
                
                g1_mulAccC(_pVk, IC3x, IC3y, calldataload(add(pubSignals, 64)))
                
                g1_mulAccC(_pVk, IC4x, IC4y, calldataload(add(pubSignals, 96)))
                
                g1_mulAccC(_pVk, IC5x, IC5y, calldataload(add(pubSignals, 128)))
                
                g1_mulAccC(_pVk, IC6x, IC6y, calldataload(add(pubSignals, 160)))
                
                g1_mulAccC(_pVk, IC7x, IC7y, calldataload(add(pubSignals, 192)))
                
                g1_mulAccC(_pVk, IC8x, IC8y, calldataload(add(pubSignals, 224)))
                
                g1_mulAccC(_pVk, IC9x, IC9y, calldataload(add(pubSignals, 256)))
                
                g1_mulAccC(_pVk, IC10x, IC10y, calldataload(add(pubSignals, 288)))
                
                g1_mulAccC(_pVk, IC11x, IC11y, calldataload(add(pubSignals, 320)))
                
                g1_mulAccC(_pVk, IC12x, IC12y, calldataload(add(pubSignals, 352)))
                
                g1_mulAccC(_pVk, IC13x, IC13y, calldataload(add(pubSignals, 384)))
                
                g1_mulAccC(_pVk, IC14x, IC14y, calldataload(add(pubSignals, 416)))
                
                g1_mulAccC(_pVk, IC15x, IC15y, calldataload(add(pubSignals, 448)))
                
                g1_mulAccC(_pVk, IC16x, IC16y, calldataload(add(pubSignals, 480)))
                
                g1_mulAccC(_pVk, IC17x, IC17y, calldataload(add(pubSignals, 512)))
                
                g1_mulAccC(_pVk, IC18x, IC18y, calldataload(add(pubSignals, 544)))
                
                g1_mulAccC(_pVk, IC19x, IC19y, calldataload(add(pubSignals, 576)))
                
                g1_mulAccC(_pVk, IC20x, IC20y, calldataload(add(pubSignals, 608)))
                
                g1_mulAccC(_pVk, IC21x, IC21y, calldataload(add(pubSignals, 640)))
                

                // -A
                mstore(_pPairing, calldataload(pA))
                mstore(add(_pPairing, 32), mod(sub(q, calldataload(add(pA, 32))), q))

                // B
                mstore(add(_pPairing, 64), calldataload(pB))
                mstore(add(_pPairing, 96), calldataload(add(pB, 32)))
                mstore(add(_pPairing, 128), calldataload(add(pB, 64)))
                mstore(add(_pPairing, 160), calldataload(add(pB, 96)))

                // alpha1
                mstore(add(_pPairing, 192), alphax)
                mstore(add(_pPairing, 224), alphay)

                // beta2
                mstore(add(_pPairing, 256), betax1)
                mstore(add(_pPairing, 288), betax2)
                mstore(add(_pPairing, 320), betay1)
                mstore(add(_pPairing, 352), betay2)

                // vk_x
                mstore(add(_pPairing, 384), mload(add(pMem, pVk)))
                mstore(add(_pPairing, 416), mload(add(pMem, add(pVk, 32))))


                // gamma2
                mstore(add(_pPairing, 448), gammax1)
                mstore(add(_pPairing, 480), gammax2)
                mstore(add(_pPairing, 512), gammay1)
                mstore(add(_pPairing, 544), gammay2)

                // C
                mstore(add(_pPairing, 576), calldataload(pC))
                mstore(add(_pPairing, 608), calldataload(add(pC, 32)))

                // delta2
                mstore(add(_pPairing, 640), deltax1)
                mstore(add(_pPairing, 672), deltax2)
                mstore(add(_pPairing, 704), deltay1)
                mstore(add(_pPairing, 736), deltay2)


                let success := staticcall(sub(gas(), 2000), 8, _pPairing, 768, _pPairing, 0x20)

                isOk := and(success, mload(_pPairing))
            }

            let pMem := mload(0x40)
            mstore(0x40, add(pMem, pLastMem))

            // Validate that all evaluations ∈ F
            
            checkField(calldataload(add(_pubSignals, 0)))
            
            checkField(calldataload(add(_pubSignals, 32)))
            
            checkField(calldataload(add(_pubSignals, 64)))
            
            checkField(calldataload(add(_pubSignals, 96)))
            
            checkField(calldataload(add(_pubSignals, 128)))
            
            checkField(calldataload(add(_pubSignals, 160)))
            
            checkField(calldataload(add(_pubSignals, 192)))
            
            checkField(calldataload(add(_pubSignals, 224)))
            
            checkField(calldataload(add(_pubSignals, 256)))
            
            checkField(calldataload(add(_pubSignals, 288)))
            
            checkField(calldataload(add(_pubSignals, 320)))
            
            checkField(calldataload(add(_pubSignals, 352)))
            
            checkField(calldataload(add(_pubSignals, 384)))
            
            checkField(calldataload(add(_pubSignals, 416)))
            
            checkField(calldataload(add(_pubSignals, 448)))
            
            checkField(calldataload(add(_pubSignals, 480)))
            
            checkField(calldataload(add(_pubSignals, 512)))
            
            checkField(calldataload(add(_pubSignals, 544)))
            
            checkField(calldataload(add(_pubSignals, 576)))
            
            checkField(calldataload(add(_pubSignals, 608)))
            
            checkField(calldataload(add(_pubSignals, 640)))
            

            // Validate all evaluations
            let isValid := checkPairing(_pA, _pB, _pC, _pubSignals, pMem)

            mstore(0, isValid)
             return(0, 0x20)
         }
     }
 }
