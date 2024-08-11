package Utilities;

/**
 *
 * @author 21701
 */
import java.io.IOException;
import java.io.OutputStream;

public class Base64Encoder {

    protected final byte[] encodingTable = new byte[]{
        65, 66, 67, 68, 69, 70, 71, 72, 73, 74,
        75, 76, 77, 78, 79, 80, 81, 82, 83, 84,
        85, 86, 87, 88, 89, 90, 97, 98, 99, 100,
        101, 102, 103, 104, 105, 106, 107, 108, 109, 110,
        111, 112, 113, 114, 115, 116, 117, 118, 119, 120,
        121, 122, 48, 49, 50, 51, 52, 53, 54, 55,
        56, 57, 43, 47};

    protected byte padding = 61;

    protected final byte[] decodingTable = new byte[128];

    protected void initialiseDecodingTable() {
        int i;
        for (i = 0; i < this.decodingTable.length; i++) {
            this.decodingTable[i] = -1;
        }
        for (i = 0; i < this.encodingTable.length; i++) {
            this.decodingTable[this.encodingTable[i]] = (byte) i;
        }
    }

    public Base64Encoder() {
        initialiseDecodingTable();
    }

    public int encode(byte[] data, int off, int length, OutputStream out) throws IOException {
        int b1, b2, b3, d1, d2, modulus = length % 3;
        int dataLength = length - modulus;
        for (int i = off; i < off + dataLength; i += 3) {
            int a1 = data[i] & 0xFF;
            int a2 = data[i + 1] & 0xFF;
            int a3 = data[i + 2] & 0xFF;
            out.write(this.encodingTable[a1 >>> 2 & 0x3F]);
            out.write(this.encodingTable[(a1 << 4 | a2 >>> 4) & 0x3F]);
            out.write(this.encodingTable[(a2 << 2 | a3 >>> 6) & 0x3F]);
            out.write(this.encodingTable[a3 & 0x3F]);
        }
        switch (modulus) {
            case 1:
                d1 = data[off + dataLength] & 0xFF;
                b1 = d1 >>> 2 & 0x3F;
                b2 = d1 << 4 & 0x3F;
                out.write(this.encodingTable[b1]);
                out.write(this.encodingTable[b2]);
                out.write(this.padding);
                out.write(this.padding);
                break;
            case 2:
                d1 = data[off + dataLength] & 0xFF;
                d2 = data[off + dataLength + 1] & 0xFF;
                b1 = d1 >>> 2 & 0x3F;
                b2 = (d1 << 4 | d2 >>> 4) & 0x3F;
                b3 = d2 << 2 & 0x3F;
                out.write(this.encodingTable[b1]);
                out.write(this.encodingTable[b2]);
                out.write(this.encodingTable[b3]);
                out.write(this.padding);
                break;
        }
        return dataLength / 3 * 4 + ((modulus == 0) ? 0 : 4);
    }
}
