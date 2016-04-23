/*	This file is part of PPdedupe, which is free software and is licensed
 * under the terms of the GNU GPL v3.0. (see http://www.gnu.org/licenses/ ) */

#include <cassert>
#include <cstdio>
#include <memory>
#include <vector>

#include <boost/crc.hpp>

class Buffer{
	private:
		std::unique_ptr<uint8_t[]> buffer;
		size_t lenght;
		
	public:
		Buffer() = default;
		Buffer( size_t lenght ) : buffer( std::make_unique<uint8_t[]>( lenght ) ), lenght(lenght) { }
		
		auto data(){ return buffer.get(); }
		auto size() const{ return lenght; }
		
		auto begin(){ return buffer.get(); }
		auto end(){ return buffer.get() + lenght; }
		
		uint8_t& operator[]( int index )       { return buffer[index]; }
		uint8_t& operator[]( int index ) const { return buffer[index]; }
};

class File{
	private:
		FILE* handle;
	
	public:
		File( const char* filepath ) : handle( std::fopen( filepath, "rb" ) ) {
			//TODO: throw on (handle == nullptr)
		}
		~File(){ std::fclose( handle ); }
		
		void read( Buffer& buf ){
			fread( buf.data(), 1, buf.size(), handle );
		}
		
		int seek( long int offset, int origin )
			{ return fseek( handle, offset, origin ); }
		
		Buffer read( size_t bytes ){
			Buffer buf( bytes );
			read( buf );
			return buf;
		}
};

unsigned convert32unsigned( uint8_t a, uint8_t b, uint8_t c, uint8_t d )
	{ return a + (b<<8) + (c<<16) + (d<<24); }

unsigned convert32unsigned( const Buffer& b ){
	assert( b.size() == 4 );
	return convert32unsigned( b[0], b[1], b[2], b[3] );
}


const uint8_t magic[] = {0x5B, 0x50, 0x50, 0x56, 0x45, 0x52, 0x5D, 0x00}; // "[PPVER]\0"

const uint8_t offset[] = {0x3A, 0xE3, 0x87, 0xC2, 0xBD, 0x1E, 0xA6, 0xFE};
class HeaderDecrypter{
	private:
		uint8_t mask[8] = {0xFA, 0x49, 0x7B, 0x1C, 0xF9, 0x4D, 0x83, 0x0A};
		uint32_t index = { 0 };
	
	public:
		void decrypt( Buffer& buffer ){
			for( auto& val : buffer ){
				auto mask_index = index % 8;
				mask[mask_index] += offset[mask_index];
				val ^= mask[mask_index];
				index++;
			}
		}
};

unsigned read32u( File& file, HeaderDecrypter& decrypter ){
	auto buf = file.read( 4 );
	decrypter.decrypt( buf );
	return convert32unsigned( buf );
}

struct SubFile{
	Buffer filename;
	uint32_t size, offset;
	Buffer metadata;
	uint32_t checksum{ 0 };
	const SubFile* deduped{ nullptr };
	
	uint32_t output_offset{ 0 };
	
	SubFile( File& file, HeaderDecrypter& decrypter ){
		filename = file.read( 260 );
		decrypter.decrypt( filename );
		size   = read32u( file, decrypter );
		offset = read32u( file, decrypter );
		
		metadata = file.read( 20 );
		decrypter.decrypt( metadata );
	}
	
	Buffer getFile( File& file ) const{
		file.seek( offset, 0 );
		return file.read( size );
	}
	
	void equalTo( const SubFile& f, File& file ){
		assert( f.checksum == checksum );
		assert( f.size == size );
		
		auto data       =   getFile( file );
		auto other_data = f.getFile( file );
		for( uint32_t i=0; i<size; i++ )
			if( data[i] != other_data[i] ){
				printf( "Files not equal even though hash-check passed!\n" );
				return;
			}
		
		offset = f.offset;
		deduped = &f;
	}
};

int main( int argc, char* argv[] ){
	if( argc < 2 )
		return -1;
	
	printf( "Reading header...\n" );
	File file( argv[1] );
	
	auto header = file.read( 8 );
	//TODO: Check magic
	
	auto temp = HeaderDecrypter();
	auto version = read32u( file, temp );
	
	HeaderDecrypter decrypter;
	auto unknown1 = file.read( 1 );
	//decrypter.decrypt( unknown1 );
	
	auto file_amount = read32u( file, decrypter );
	decrypter = HeaderDecrypter();
	
	std::vector<SubFile> files;
	files.reserve( file_amount );
	for( int i=0; i<file_amount; i++ )
		files.emplace_back( file, decrypter );
	
	printf( "Calculating checksums...\n" );
	for( auto& subfile : files ){
		auto bytes = subfile.getFile( file );
		boost::crc_32_type crc;
		crc.process_bytes( bytes.data(), bytes.size() );
		subfile.checksum = crc.checksum();
		
	//	printf( "%X - %s\n", subfile.checksum, subfile.filename.data() );
	}
	
	printf( "Finding dupes...\n" );
	for( int i=0; i<files.size(); i++ ){
		auto& current = files[i];
		if( current.deduped )
			continue;
		
		for( int j=i+1; j<files.size(); j++ )
			if( current.checksum == files[j].checksum )
				files[j].equalTo( current, file );
	}
	
	printf( "De-fragmenting file... (TODO)\n" );
	
	
	printf( "Saving file... (TODO)\n" );
	
	
	printf( "\n-------- Result --------\n" );
	unsigned saved_bytes = 0;
	unsigned used_bytes = 0;
	unsigned duped_files = 0;
	for( auto& subfile : files )
		if( subfile.deduped ){
			saved_bytes += subfile.size;
			duped_files++;
		}
		else
			used_bytes += subfile.size;
	
	printf( "Duplicated files: %u\n", duped_files );
	printf( "Total saved:         %10u bytes\n", saved_bytes );
	printf( "Resulting data size: %10u bytes\n", used_bytes );
	printf( "Old data size:       %10u bytes\n", saved_bytes + used_bytes );
	
	return 0;
}

