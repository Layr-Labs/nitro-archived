package eigenda_blobs

import (
	"math"

	"github.com/Layr-Labs/eigenda/encoding/fft"
	"github.com/Layr-Labs/eigenda/encoding/kzg"
	"github.com/Layr-Labs/eigenda/encoding/rs"
	"github.com/Layr-Labs/eigenda/encoding/utils/codec"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/ethereum/go-ethereum/params"
)

// The number of bits in a BLS scalar that aren't part of a whole byte.
const spareBlobBits = 6 // = math.floor(math.log2(BLS_MODULUS)) % 8

// The number of bytes encodable in a blob with the current encoding scheme.
const BlobEncodableData = 254 * params.BlobTxFieldElementsPerBlob / 8

var GenG1 []bn254.G1Affine
var GenG2 []bn254.G2Affine

const SrsOrder = 3000
const SrsNumberToLoad = 3000

func loadGenG1(g1Path string) error {
	g1, err := kzg.ReadG1Points(g1Path, SrsOrder, SrsNumberToLoad)
	if err != nil {
		return err
	}

	GenG1 = g1
	return nil
}

func ComputeCommitmentToData(data []byte) (*bn254.G1Affine, error) {
	var commitment bn254.G1Affine

	dataFr, err := ConvertToPaddedFieldElements(data)
	if err != nil {
		return nil, err
	}

	_, err = commitment.MultiExp(GenG1[:len(dataFr)], dataFr, ecc.MultiExpConfig{})
	return &commitment, err
}

func ComputeIFFT(data []byte) ([]fr.Element, error) {
	//convert to padded field elements
	paddedBlobFr, err := ConvertToPaddedFieldElements(data)
	if err != nil {
		return nil, err
	}
	blobLengthPowOf2 := uint64(len(paddedBlobFr))

	n := uint8(math.Log2(float64(blobLengthPowOf2)))
	fs := fft.NewFFTSettings(n)

	ifftFr, err := fs.FFT(paddedBlobFr, true)
	if err != nil {
		return nil, err
	}

	return ifftFr, nil
}

func ComputeFFT(data []byte) ([]fr.Element, error) {
	// convert to padded field elements
	paddedBlobFr, err := ConvertToPaddedFieldElements(data)
	if err != nil {
		return nil, err
	}
	blobLengthPowOf2 := uint64(len(paddedBlobFr))

	n := uint8(math.Log2(float64(blobLengthPowOf2)))
	fs := fft.NewFFTSettings(n)

	fftFr, err := fs.FFT(paddedBlobFr, true)
	if err != nil {
		return nil, err
	}

	return fftFr, nil
}

func ConvertToPaddedFieldElements(data []byte) ([]fr.Element, error) {
	frArray, err := rs.ToFrArray(data)
	if err != nil {
		return nil, err
	}
	paddedFrArray := padFrArrayToNextPowerOfTwo(frArray)
	return paddedFrArray, nil
}

func padFrArrayToNextPowerOfTwo(dataFr []fr.Element) []fr.Element {
	currentLength := uint64(len(dataFr))
	nextPowerLength := rs.NextPowerOf2(currentLength)

	padding := make([]fr.Element, nextPowerLength-currentLength)
	for i := range padding {
		padding[i].SetZero()
	}

	return append(dataFr, padding...)
}

func EncodeBlob(data []byte) ([]byte, error) {
	ifftDataFr, err := ComputeIFFT(data)
	if err != nil {
		return nil, err
	}
	ifftDataBytes := rs.ToByteArray(ifftDataFr, uint64(len(ifftDataFr)))

	// need to use this to make sure every 32 bytes is less than the field element in bn254 curve
	encodedData := codec.ConvertByPaddingEmptyByte(ifftDataBytes)
	return encodedData, nil
}

func DecodeBlob(data []byte) ([]byte, error) {
	fftDataFr, err := ComputeFFT(data)
	if err != nil {
		return nil, err
	}
	fftDataBytes := rs.ToByteArray(fftDataFr, uint64(len(fftDataFr)))

	decodedData := codec.RemoveEmptyByteFromPaddedBytes(fftDataBytes)
	return decodedData, nil

}
