// Copyright 2024-2024, Alt Research, Inc.
// For license information, see https://github.com/nitro/blob/master/LICENSE

package eigenda

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/Layr-Labs/eigenda/api/grpc/disperser"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/log"
	"github.com/offchainlabs/nitro/arbutil"
	eigenda_blobs "github.com/offchainlabs/nitro/util/eigenda"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// EigenDAMessageHeaderFlag indicated that the message is a EigenDABlobID which will be used to retrieve data from EigenDA
const EigenDAMessageHeaderFlag byte = 0xed

func IsEigenDAMessageHeaderByte(header byte) bool {
	return (EigenDAMessageHeaderFlag & header) > 0
}

type EigenDAWriter interface {
	Store(context.Context, []byte) (*EigenDABlobID, *EigenDABlobInfo, error)
	Serialize(eigenDABlobID *EigenDABlobID) ([]byte, error)
}

type EigenDAReader interface {
	QueryBlob(ctx context.Context, id *EigenDABlobID) ([]byte, error)
}

type EigenDAConfig struct {
	Enable bool   `koanf:"enable"`
	Rpc    string `koanf:"rpc"`
}

func (ec *EigenDAConfig) String() {
	fmt.Println(ec.Enable)
	fmt.Println(ec.Rpc)
	// fmt.Sprintf("enable: %b, rpc: %s", ec.Enable, ec.Rpc)
}

type EigenDABlobID struct {
	BatchHeaderHash      []byte
	BlobIndex            uint32
	ReferenceBlockNumber uint32
	QuorumIDs            []uint32
}

type EigenDABlobInfo struct {
	BlobHeader            BlobHeader
	BlobVerificationProof BlobVerificationProof
}

type BlobHeader struct {
	Commitment       *G1Point
	DataLength       uint32
	QuorumBlobParams []*QuorumBlobParams
}

type G1Point struct {
	X *big.Int
	Y *big.Int
}

type QuorumBlobParams struct {
	QuorumNumber                    uint8
	AdversaryThresholdPercentage    uint8
	ConfirmationThresholdPercentage uint8
	ChunkLength                     uint32
}

type BlobVerificationProof struct {
	BatchID        uint32
	BlobIndex      uint32
	BatchMetadata  *BatchMetadata
	InclusionProof []byte
	QuorumIndices  []byte
}

type BatchMetadata struct {
	BatchHeader             *BatchHeader
	SignatoryRecordHash     [32]byte
	ConfirmationBlockNumber uint32
}

type BatchHeader struct {
	BlobHeadersRoot       [32]byte
	QuorumNumbers         []byte
	SignedStakeForQuorums []byte
	ReferenceBlockNumber  uint32
}

func (b *EigenDABlobID) Serialize() ([]byte, error) {
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.BigEndian, b.BlobIndex)
	if err != nil {
		return nil, err
	}
	_, err = buf.Write(b.BatchHeaderHash)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (b *EigenDABlobID) Deserialize(data []byte) error {
	buf := bytes.NewReader(data)
	err := binary.Read(buf, binary.BigEndian, &b.BlobIndex)
	if err != nil {
		return err
	}
	// _, err = buf.Read(b.BatchHeaderHash)
	err = binary.Read(buf, binary.BigEndian, &b.BatchHeaderHash)
	if err != nil {
		return err
	}
	return nil
}

type EigenDA struct {
	client disperser.DisperserClient
}

func NewEigenDA(rpc string) (*EigenDA, error) {
	creds := credentials.NewTLS(&tls.Config{
		InsecureSkipVerify: true,
	})
	conn, err := grpc.Dial(rpc, grpc.WithTransportCredentials(creds))
	if err != nil {
		return nil, err
	}
	return &EigenDA{
		client: disperser.NewDisperserClient(conn),
	}, nil
}

// TODO: There should probably be two types of query blob as the
func (e *EigenDA) QueryBlob(ctx context.Context, id *EigenDABlobID) ([]byte, error) {
	res, err := e.client.RetrieveBlob(ctx, &disperser.RetrieveBlobRequest{
		BatchHeaderHash: id.BatchHeaderHash,
		BlobIndex:       id.BlobIndex,
	})
	if err != nil {
		return nil, err
	}
	decodedData, err := eigenda_blobs.DecodeBlob(res.GetData())
	if err != nil {
		return nil, err
	}
	return decodedData, nil
}

func (e *EigenDA) Store(ctx context.Context, data []byte) (*EigenDABlobID, *EigenDABlobInfo, error) {

	encodedData, err := eigenda_blobs.EncodeBlob(data)
	if err != nil {
		return nil, nil, err
	}

	expectedDataCommitment, err := eigenda_blobs.ComputeCommitmentToData(encodedData)
	if err != nil {
		return nil, nil, err
	}

	disperseBlobRequest := &disperser.DisperseBlobRequest{
		Data: encodedData,
	}

	res, err := e.client.DisperseBlob(ctx, disperseBlobRequest)
	if err != nil {
		return nil, nil, err
	}

	ticker := time.NewTicker(time.Second * 5)
	defer ticker.Stop()

	var id *EigenDABlobID
	var info *EigenDABlobInfo
	for range ticker.C {
		statusReply, err := e.GetBlobStatus(ctx, res.GetRequestId())
		if err != nil {
			log.Error("[eigenda]: GetBlobStatus: ", "error", err.Error())
			continue
		}
		switch statusReply.GetStatus() {
		case disperser.BlobStatus_CONFIRMED, disperser.BlobStatus_FINALIZED:

			quorumIDs, err := bytesToUint32Array(statusReply.GetInfo().GetBlobVerificationProof().GetBatchMetadata().GetBatchHeader().GetQuorumNumbers())
			if err != nil {
				log.Error("[eigenda]: GetBlobStatus: ", "error", err.Error())
				continue
			}

			id = &EigenDABlobID{
				BatchHeaderHash:      statusReply.GetInfo().GetBlobVerificationProof().GetBatchMetadata().GetBatchHeaderHash(),
				BlobIndex:            statusReply.GetInfo().GetBlobVerificationProof().GetBlobIndex(),
				ReferenceBlockNumber: statusReply.GetInfo().GetBlobVerificationProof().GetBatchMetadata().GetBatchHeader().GetReferenceBlockNumber(),
				QuorumIDs:            quorumIDs,
			}

			info = &EigenDABlobInfo{}
			info.loadBlobInfo(statusReply.GetInfo())

			dataCommitment := statusReply.GetInfo().GetBlobHeader().GetCommitment()

			// verify the blob commitment matches the transformed data by computing the comitment ourselves
			if expectedDataCommitment.String() != dataCommitment.String() {
				return nil, nil, errors.New("commitment does not match expected")
			}

			return id, info, nil
		case disperser.BlobStatus_FAILED:
			return nil, nil, errors.New("disperser blob failed")
		default:
			continue
		}
	}

	return nil, nil, errors.New("disperser blob query status timeout")

}

func (b *EigenDABlobInfo) loadBlobInfo(disperserBlobInfo *disperser.BlobInfo) {
	b.BlobHeader.Commitment = &G1Point{
		X: new(big.Int).SetBytes(disperserBlobInfo.GetBlobHeader().GetCommitment().GetX()),
		Y: new(big.Int).SetBytes(disperserBlobInfo.GetBlobHeader().GetCommitment().GetY()),
	}

	b.BlobHeader.DataLength = disperserBlobInfo.GetBlobHeader().GetDataLength()

	for _, quorumBlobParam := range disperserBlobInfo.GetBlobHeader().GetBlobQuorumParams() {
		b.BlobHeader.QuorumBlobParams = append(b.BlobHeader.QuorumBlobParams, &QuorumBlobParams{
			QuorumNumber:                    uint8(quorumBlobParam.QuorumNumber),
			AdversaryThresholdPercentage:    uint8(quorumBlobParam.AdversaryThresholdPercentage),
			ConfirmationThresholdPercentage: uint8(quorumBlobParam.ConfirmationThresholdPercentage),
			ChunkLength:                     quorumBlobParam.ChunkLength,
		})
	}

	var signatoryRecordHash [32]byte
	copy(signatoryRecordHash[:], disperserBlobInfo.GetBlobVerificationProof().GetBatchMetadata().GetSignatoryRecordHash())

	b.BlobVerificationProof.BatchID = disperserBlobInfo.GetBlobVerificationProof().GetBatchId()
	b.BlobVerificationProof.BlobIndex = disperserBlobInfo.GetBlobVerificationProof().GetBlobIndex()
	b.BlobVerificationProof.BatchMetadata = &BatchMetadata{
		BatchHeader:             &BatchHeader{},
		SignatoryRecordHash:     signatoryRecordHash,
		ConfirmationBlockNumber: disperserBlobInfo.GetBlobVerificationProof().GetBatchMetadata().GetConfirmationBlockNumber(),
	}

	b.BlobVerificationProof.InclusionProof = disperserBlobInfo.GetBlobVerificationProof().GetInclusionProof()
	b.BlobVerificationProof.QuorumIndices = disperserBlobInfo.GetBlobVerificationProof().GetQuorumIndexes()

	b.BlobVerificationProof.BatchMetadata.BatchHeader.BlobHeadersRoot = disperserBlobInfo.GetBlobVerificationProof().GetBatchMetadata().GetBatchHeader().GetBlobHeadersRoot()
	b.BlobVerificationProof.BatchMetadata.BatchHeader.QuorumNumbers = disperserBlobInfo.GetBlobVerificationProof().GetBatchMetadata().GetBatchHeader().GetQuorumNumbers()
	b.BlobVerificationProof.BatchMetadata.BatchHeader.SignedStakeForQuorums = disperserBlobInfo.GetBlobVerificationProof().GetBatchMetadata().GetBatchHeader().GetSignedStakeForQuorums()
	b.BlobVerificationProof.BatchMetadata.BatchHeader.ReferenceBlockNumber = disperserBlobInfo.GetBlobVerificationProof().GetBatchMetadata().GetBatchHeader().GetReferenceBlockNumber()
}

func (e *EigenDA) GetBlobStatus(ctx context.Context, reqeustId []byte) (*disperser.BlobStatusReply, error) {
	blockStatusRequest := &disperser.BlobStatusRequest{
		RequestId: reqeustId,
	}
	return e.client.GetBlobStatus(ctx, blockStatusRequest)
}

// Serialize implements EigenDAWriter.
func (e *EigenDA) Serialize(EigenDABlobID *EigenDABlobID) ([]byte, error) {
	EigenDABlobIDData, err := EigenDABlobID.Serialize()
	if err != nil {
		log.Warn("EigenDABlobID serialize error", "err", err)
		return nil, err
	}
	buf := new(bytes.Buffer)
	err = binary.Write(buf, binary.BigEndian, EigenDAMessageHeaderFlag)
	if err != nil {
		log.Warn("batch type byte serialization failed", "err", err)
		return nil, err
	}
	err = binary.Write(buf, binary.BigEndian, EigenDABlobIDData)

	if err != nil {
		log.Warn("data pointer serialization failed", "err", err)
		return nil, err
	}
	serializedBlobPointerData := buf.Bytes()
	return serializedBlobPointerData, nil
}

// new hash format is different now:
// ed + abi.encode

// calldata layout of addSequencerL2BatchFromEigenDA looks like the following:
// 0-4 function signature
// 4-36 sequencer
func RecoverPayloadFromEigenDABatch(ctx context.Context,
	sequencerMsg []byte, // this is literally the calldata of the transaction/
	daReader EigenDAReader,
	preimages map[arbutil.PreimageType]map[common.Hash][]byte,
) ([]byte, error) {
	log.Info("Start recovering payload from eigenda: ", "data", hex.EncodeToString(sequencerMsg))
	var shaPreimages map[common.Hash][]byte
	if preimages != nil {
		if preimages[arbutil.Sha2_256PreimageType] == nil {
			preimages[arbutil.Sha2_256PreimageType] = make(map[common.Hash][]byte)
		}
		shaPreimages = preimages[arbutil.Sha2_256PreimageType]
	}
	daBlobID := ParseSequencerMsg(sequencerMsg)

	log.Info("Data pointer: ", "info", hex.EncodeToString(daBlobID.BatchHeaderHash), "index", daBlobID.BlobIndex)

	data, err := daReader.QueryBlob(ctx, daBlobID)
	if err != nil {
		log.Error("Failed to query data from EigenDA", "err", err)
		return nil, err
	}

	// record preimage data
	log.Info("Recording preimage data for EigenDA")
	shaDataHash := sha256.New()
	shaDataHash.Write(sequencerMsg)
	dataHash := shaDataHash.Sum([]byte{})
	if shaPreimages != nil {
		shaPreimages[common.BytesToHash(dataHash)] = data
	}
	return data, nil
}

// calldata layout of sequencer msg
// [inclusive - exclusive]
// [0 - 4]    Function Selector (4 bytes)
// [4 - 36]   sequenceNumber (uint256)
// [36 - 68]  Offset to BlobVerificationProof (dynamic, calculated based on starting point of the dynamic section)
// [68 - 100] Offset to BlobHeader (dynamic, calculated)
// [100 - 132] afterDelayedMessagesRead (uint256)
// [132 - 164] gasRefunder (address)
// [164 - 196] prevMessageCount (uint256)
// [196 - 228] newMessageCount (uint256)

// BlobVerificationProof START
// [BVP offset - BVP offset + 32]  BlobVerificationProof.batchId (uint32, padded)
// [BVP offset + 32 - BVP offset + 64]  BlobVerificationProof.blobIndex (uint32, padded)
// [BVP offset + 64 - BVP offset + 96]  Offset to BlobVerificationProof.BatchMetadata (from BlobVerificationProof start)
// [BVP offset + 96 - BVP offset + 128]  Offset to BlobVerificationProof.inclusionProof (from BlobVerificationProof start)
// [BVP offset + 128 - BVP offset + 160]  Offset to BlobVerificationProof.quorumIndices (from BlobVerificationProof start)

// BatchMetadata START
// [BatchMeta offset - BatchMeta offset + 32]  Offset to BatchMetadata.batchHeader (from BatchMeta start)
// [BatchMeta offset + 32 - BatchMeta offset + 64]  BatchMetadata.signatoryRecordHash (bytes32)
// [BatchMeta offset + 64 - BatchMeta offset + 96]  BatchMetadata.confirmationBlockNumber (uint32, padded)

// BatchHeader START
// [BatchHeader offset - BatchHeader offset + 32]  BatchHeader.blobHeadersRoot (bytes32)
// [BatchHeader offset + 32 - BatchHeader offset + 64]  offset of BatchHeader.quorumNumbers
// [BatchHeader offset + 64 - BatchHeader offset + 96]  offset of BatchHeader.signedStakeForQuorums
// [BatchHeader offset + 96 - BatchHeader offset + 128]  BatchHeader.referenceBlockNumber (uint32, padded)

// BlobHeader Start
// [BlobHeader offset - BlobHeader offset + 32]  BlobHeader.commitment.X (uint256)
// [BlobHeader offset + 32 - BlobHeader offset + 64]  BlobHeader.commitment.Y (uint256)
// [BlobHeader offset + 64 - BlobHeader offset + 96]  BlobHeader.dataLength (uint32, padded)
// [BlobHeader offset + 96 - BlobHeader offset + 128]  Offset to BlobHeader.quorumBlobParams (from BlobHeader start)

// QuorumBlobParams Start
// Assuming `n` elements in quorumBlobParams
// [QBP Start - QBP Start + 32]  Number of elements in quorumBlobParams
// we only need the first 32 bytes every 32*n bytes in this one

// InclusionProof

func ParseSequencerMsg(calldata []byte) *EigenDABlobID {

	blobVerificationProofOffset, err := convertCalldataToInt(calldata[36:68])
	if err != nil {
		panic(err)
	}

	blobVerificationProofOffset += 4

	blobHeaderOffset, err := convertCalldataToInt(calldata[68:100])
	if err != nil {
		panic(err)
	}

	blobHeaderOffset += 4
	blobIndex, err := convertCalldataToInt(calldata[blobVerificationProofOffset+32 : blobVerificationProofOffset+64])

	batchMetadataOffset, err := convertCalldataToInt(calldata[blobVerificationProofOffset+64 : blobVerificationProofOffset+96])
	if err != nil {
		panic(err)
	}

	batchMetadataOffset += blobVerificationProofOffset

	batchHeaderOffset, err := convertCalldataToInt(calldata[batchMetadataOffset : batchMetadataOffset+32])
	if err != nil {
		panic(err)
	}

	batchHeaderOffset += batchMetadataOffset
	blobHeadersRoot := calldata[batchHeaderOffset : batchHeaderOffset+32]
	referenceBlockNumber, err := convertCalldataToInt(calldata[batchHeaderOffset+96 : batchHeaderOffset+128])

	quorumBlobParamsOffset, err := convertCalldataToInt(calldata[blobHeaderOffset+96 : blobHeaderOffset+128])
	if err != nil {
		panic(err)
	}
	quorumBlobParamsOffset += blobHeaderOffset

	numberOfQuorumBlobParams, err := convertCalldataToInt(calldata[quorumBlobParamsOffset : quorumBlobParamsOffset+32])
	if err != nil {
		panic(err)
	}

	quorumIDs := make([]uint32, numberOfQuorumBlobParams)

	for i := 0; i < numberOfQuorumBlobParams; i++ {
		offset := quorumBlobParamsOffset + 32 + 32*4*i
		quorumID, err := convertCalldataToInt(calldata[offset : offset+32])
		if err != nil {
			panic(err)
		}

		quorumIDs[i] = uint32(quorumID)
	}

	batchHeader := append(blobHeadersRoot, calldata[batchHeaderOffset+96:batchHeaderOffset+128]...)
	batchHeaderHash := crypto.Keccak256Hash(batchHeader).Bytes()

	return &EigenDABlobID{
		BatchHeaderHash:      batchHeaderHash,
		BlobIndex:            uint32(blobIndex),
		ReferenceBlockNumber: uint32(referenceBlockNumber),
		QuorumIDs:            quorumIDs,
	}

}

func convertCalldataToInt(calldata []byte) (int, error) {
	num := new(big.Int).SetBytes(calldata)

	if num.IsInt64() {
		return int(num.Uint64()), nil
	}

	fmt.Println(num)

	return 0, errors.New("calldata is not a valid int")
}

func bytesToUint32Array(b []byte) ([]uint32, error) {
	if len(b)%4 != 0 {
		return nil, fmt.Errorf("the length of the byte slice must be a multiple of 4")
	}

	numElements := len(b) / 4
	result := make([]uint32, numElements)
	for i := 0; i < numElements; i++ {
		result[i] = binary.BigEndian.Uint32(b[i*4 : (i+1)*4])
	}

	return result, nil
}
