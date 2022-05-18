package message

import "bytes"

func fake250BytesTx(clientId, reqCount, peerId int) []byte {
	var buffer bytes.Buffer
	buffer.WriteByte(byte(clientId))
	buffer.WriteByte('-')
	buffer.WriteByte(byte(reqCount))
	buffer.WriteByte('-')
	buffer.WriteByte(byte(peerId))
	for i := 0; i < 245; i++ {
		buffer.WriteByte('.')
	}
	return buffer.Bytes()
}

func FakeBatchTx(batchSize, clientId, reqCount, peerId int) [][]byte {
	txs := make([][]byte, batchSize)
	for i := 0; i < batchSize; i++ {
		txs[i] = fake250BytesTx(clientId, reqCount, peerId)
	}
	return txs
}
