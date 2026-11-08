package digest_test

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/digest"
)

func TestAlgorithm_String(t *testing.T) {
	assert.Equal(t, "sha256", digest.SHA256.String())
	assert.Equal(t, "sha1", digest.SHA1.String())
}

func TestNewDigest(t *testing.T) {
	h := sha256.New()
	_, err := h.Write([]byte("hello"))
	require.NoError(t, err)

	got := digest.NewDigest(digest.SHA256, h)
	assert.Equal(t, digest.Digest("sha256:2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"), got)
}

func TestNewDigestFromString(t *testing.T) {
	got := digest.NewDigestFromString(digest.SHA256, "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824")
	assert.Equal(t, digest.Digest("sha256:2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"), got)
}

func TestDigest_Parts(t *testing.T) {
	d := digest.Digest("sha256:2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824")
	assert.Equal(t, digest.SHA256, d.Algorithm())
	assert.Equal(t, "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824", d.Encoded())
	assert.Equal(t, "sha256:2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824", d.String())
}

func TestCalcSHA256(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
		want  digest.Digest
	}{
		{
			name:  "empty",
			input: []byte{},
			want:  "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		},
		{
			name:  "hello",
			input: []byte("hello"),
			want:  "sha256:2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, digest.CalcSHA256(tt.input))
		})
	}
}

func TestCalcSHA256FromReader(t *testing.T) {
	t.Run("happy path seeks the reader back to the start", func(t *testing.T) {
		r := bytes.NewReader([]byte("hello"))
		_, err := r.Seek(2, io.SeekStart) // Start from a non-zero offset
		require.NoError(t, err)

		// Only the remaining bytes are hashed, ...
		got, err := digest.CalcSHA256FromReader(r)
		require.NoError(t, err)
		assert.Equal(t, digest.CalcSHA256([]byte("llo")), got)

		// ... but the reader is rewound afterwards.
		off, err := r.Seek(0, io.SeekCurrent)
		require.NoError(t, err)
		assert.Zero(t, off)
	})

	t.Run("read error", func(t *testing.T) {
		_, err := digest.CalcSHA256FromReader(errReadSeeker{})
		require.ErrorContains(t, err, "unable to calculate sha256 digest")
	})
}

func TestCalcSHA1(t *testing.T) {
	t.Run("happy path seeks the reader back to the start", func(t *testing.T) {
		r := bytes.NewReader([]byte("hello"))

		got, err := digest.CalcSHA1(r)
		require.NoError(t, err)
		assert.Equal(t, digest.Digest("sha1:aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d"), got)

		off, err := r.Seek(0, io.SeekCurrent)
		require.NoError(t, err)
		assert.Zero(t, off)
	})

	t.Run("read error", func(t *testing.T) {
		_, err := digest.CalcSHA1(errReadSeeker{})
		require.ErrorContains(t, err, "unable to calculate sha1 digest")
	})
}

type errReadSeeker struct{}

func (errReadSeeker) Read([]byte) (int, error) {
	return 0, errors.New("read error")
}

func (errReadSeeker) Seek(int64, int) (int64, error) {
	return 0, nil
}
