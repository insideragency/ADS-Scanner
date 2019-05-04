##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary

  # Exploit mixins should be called first
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::WmapScanServer
  # Scanner mixin should be near last
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize
    super(
      'Name'        => 'ads.txt File Scanner',
      'Description' => 'Detect ads.txt files or Authorized Digital Sellers, standard created by IAB Tech lab (https://iabtechlab.com), which is a text file that companies can host on their web servers that lists the third-parties authorized to sell their products or services. It is designed to allow online buyers to check the validity of the sellers from whom they buy, for the purposes of internet fraud prevention. Great recon and planning tool for security assessments. Also a great way to find subdomains.',
      'Author'       => ['Aaron Crawford - www.theinsideragency.com'],
      'License'     => MSF_LICENSE
    )

    register_options(
      [
        OptString.new('PATH', [ true,  "The path to find the existence of ads.txt files", '/']),

      ])

  end

  def run_host(target_host)

    tpath = normalize_uri(datastore['PATH'])
    if tpath[-1,1] != '/'
      tpath += '/'
    end

    begin
      turl = tpath+'ads.txt'

      res = send_request_raw({
        'uri'     => turl,
        'method'  => 'GET',
        'version' => '1.0',
      }, 10)


      if not res
        print_error("[#{target_host}] #{tpath}ads.txt - No response")
        return
      end

      print_status("[#{target_host}] #{tpath}ads.txt found")
     
      aregex = /llow:[ ]{0,2}(.*?)$/i

      result = res.body.scan(aregex).flatten.map{ |s| s.strip }.uniq

      vprint_status("[#{target_host}] #{tpath}ads.txt - #{result.join(', ')}")
      result.each do |u|
        report_note(
          :host	=> target_host,
          :port	=> rport,
          :proto => 'tcp',
          :sname	=> (ssl ? 'https' : 'http'),
          :type	=> 'ADS_TXT',
          :data	=> u,
          :update => :unique_data
        )
      end

    rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
    rescue ::Timeout::Error, ::Errno::EPIPE
    end
  end
end
