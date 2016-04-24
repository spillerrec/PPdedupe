/*	This file is part of PPdedupe, which is free software and is licensed
 * under the terms of the GNU GPL v3.0. (see http://www.gnu.org/licenses/ ) */

#include <algorithm>
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
		Buffer( const uint8_t* data, size_t lenght ) : Buffer( lenght )
			{ std::copy( data, data+lenght, buffer.get() ); }
		
		auto data(){ return buffer.get(); }
		const uint8_t* data() const{ return buffer.get(); }
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
		File( const char* filepath, const char* const modifier="rb" ) : handle( std::fopen( filepath, modifier ) ) {
			//TODO: throw on (handle == nullptr)
		}
		~File(){ std::fclose( handle ); }
		
		void read(        Buffer& buf ) { fread(  buf.data(), 1, buf.size(), handle ); }
		void write( const Buffer& buf ) { fwrite( buf.data(), 1, buf.size(), handle ); }
		unsigned long int currentOffset(){ return ftell( handle ); } //TODO: throw on -1L
		
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

Buffer unsigned32ToBuffer( uint32_t value ){
	Buffer buf( 4 );
	for( int i=0; i<4; i++ ){
		buf[i] = value % 256;
		value /= 256;
	}
	assert( value == 0 );
	
	return buf;
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
		
		Buffer encrypt( const Buffer& buffer ){
			Buffer copy( buffer.data(), buffer.size() );
			decrypt( copy );
			return copy;
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
	
	void writeHeader( File& file, HeaderDecrypter& encrypter ){
		file.write( encrypter.encrypt( filename ) );
		file.write( encrypter.encrypt( unsigned32ToBuffer( size ) ) );
		file.write( encrypter.encrypt( unsigned32ToBuffer( output_offset ) ) );
		file.write( encrypter.encrypt( metadata ) );
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

void dedupePP( const char* filepath ){
	printf( "Processing file: %s\n", filepath );
	printf( "Reading header...\n" );
	File file( filepath );
	
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
	for( unsigned i=0; i<file_amount; i++ )
		files.emplace_back( file, decrypter );
	
	decrypter = HeaderDecrypter();
	auto header_lenght = read32u( file, decrypter );
	
	printf( "Calculating checksums...\n" );
	for( auto& subfile : files ){
		auto bytes = subfile.getFile( file );
		boost::crc_32_type crc;
		crc.process_bytes( bytes.data(), bytes.size() );
		subfile.checksum = crc.checksum();
		
	//	printf( "%X - %s\n", subfile.checksum, subfile.filename.data() );
	}
	
	
	printf( "Finding dupes...\n" );
	for( unsigned i=0; i<files.size(); i++ ){
		auto& current = files[i];
		if( current.deduped )
			continue;
		
		for( unsigned j=i+1; j<files.size(); j++ )
			if( current.checksum == files[j].checksum )
				files[j].equalTo( current, file );
	}
	
	
	printf( "Calculates new offsets file...\n" );
	uint32_t offset = 17 + 288*files.size() + 4; //This is the end of the header (at least it should be)
	
	for( auto& subfile : files ){
		if( subfile.deduped )
			subfile.output_offset = subfile.deduped->output_offset;
		else{
			subfile.output_offset = offset;
			offset += subfile.size;
		}
	}
	
	
	printf( "Saving file...\n" );
	auto output_filename = std::string( filepath ) + ".deduped.pp";
	File outfile( output_filename.c_str(), "wb" );
	outfile.write( { magic, sizeof(magic) } );
	outfile.write( HeaderDecrypter().encrypt( unsigned32ToBuffer( version ) ) );
	outfile.write( unknown1 );
	outfile.write( HeaderDecrypter().encrypt( unsigned32ToBuffer( files.size() ) ) );
	
	HeaderDecrypter encrypter;
	for( auto& subfile : files )
		subfile.writeHeader( outfile, encrypter );
	
	auto new_header_lenght = outfile.currentOffset() + 4;
	assert( header_lenght == new_header_lenght );
	outfile.write( HeaderDecrypter().encrypt( unsigned32ToBuffer( new_header_lenght ) ) );
	
	for( auto& subfile : files ){
		if( !subfile.deduped ){
			assert( outfile.currentOffset() == subfile.output_offset );
			outfile.write( subfile.getFile( file ) );
		}
	}
	
	
	printf( "\n-------- Result --------\n" );
	unsigned used_bytes = offset;
	unsigned saved_bytes = 0;
	unsigned duped_files = 0;
	for( auto& subfile : files )
		if( subfile.deduped ){
			saved_bytes += subfile.size;
			duped_files++;
		}
	
	printf( "Duplicated files: %u\n", duped_files );
	printf( "Total saved:         %10u bytes\n", saved_bytes );
	printf( "Resulting data size: %10u bytes\n", used_bytes );
	printf( "Old data size:       %10u bytes\n", saved_bytes + used_bytes );
	printf( "\n\n" );
}


int main( int argc, char* argv[] ){
	if( argc < 2 ){
		printf( "PPdedupe PP_FILE_PATH ...\n" );
		return -1;
	}
	
	for( int i=1; i<argc; i++ )
		dedupePP( argv[i] );
	
	return 0;
}
