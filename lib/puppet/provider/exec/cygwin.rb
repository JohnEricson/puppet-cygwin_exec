require 'puppet/provider/exec'
require 'logger'

# To make this work on non Windows as well. Inspired by:
# https://projects.puppetlabs.com/issues/11276#note-23
# https://github.com/badgerious/puppet-windows-env/blob/master/lib/puppet/provider/windows_env/windows_env.rb
if Puppet.features.microsoft_windows?
	require 'win32/registry'
end

#require 'puppet/util/feature'

Puppet::Type.type(:exec).provide :cygwin, :parent => Puppet::Provider::Exec do
  # defaultfor :operatingsystem => :windows
  confine :operatingsystem => :windows

  
	# What is var?
	def initialize(var)	
		super(var)
		# https://ask.puppetlabs.com/question/3644/how-do-i-debug-custom-functions/
	  @log = Logger.new(STDOUT)
	  @log.level = Logger::INFO
	  #@log.info("Type cygwin initialized.")
	end
  
  #commands :bash =>  
  #  # rootdir = get_cygwin_dir_from_registry
  #  if rootdir != ''
  #    "#{rootdir}\\bash.exe"
  #  else
  #    'bash.exe'
  #  end

  desc <<-EOT
    Executes Cygwinl commands. One of the `onlyif`, `unless`, or `creates`
    parameters should be specified to ensure the command is idempotent.

    Example:
        # Rename the Guest account
        exec { 'test_cygwin':
          command   => 'ls -l /',
          # unless    => 'if (Get-WmiObject Win32_UserAccount -Filter "Name=\'guest\'") { exit 1 }',
          provider  => cygwin,
        }
  EOT

  def run(command, check = false)
    @log.info("run begin. command: #{command}")
    write_script(command) do |native_path|
      # Ideally, we could keep a handle open on the temp file in this
      # process (to prevent TOCTOU attacks), and execute powershell
      # with -File <path>. But powershell complains that it can't open
      # the file for exclusive access. If we close the handle, then an
      # attacker could modify the file before we invoke powershell. So
      # we redirect powershell's stdin to read from the file. Current
      # versions of Windows use per-user temp directories with strong
      # permissions, but I'd rather not make (poor) assumptions.
      # return super("cmd.exe /c \"\"#{native_path(command(:powershell))}\" #{args} -Command - < \"#{native_path}\"\"", check)
      
			Win32::Registry::HKEY_LOCAL_MACHINE.open('SOFTWARE\Cygwin\setup') do |reg|
				reg_typ, reg_val = reg.read('rootdir')
				#return reg_val
				@rootdir = reg_val
				#@log.info("rootdir: #{@rootdir}")
			end
			
			if @rootdir != ''
				@cmd = "#{@rootdir}\\bin\\bash.exe"
			else
				@cmd = 'bash.exe'
			end
			
			@cmd_return = "cmd.exe /c \"\"#{@cmd}\" #{args} \"#{native_path}\""
			#@log.info("cmd_return: #{@cmd_return}")
		                
	    #return super("cmd.exe /c \"\"#{native_path(cmd)}\" #{args} -c \"#{native_path}\"", check)
	    #return super(@cmd_return, check) # Works directly on easy commands. Such as those without &.
      return super(@cmd_return, check)
      
    end
  end

  #def get_cygwin_dir_from_registry
  #  Win32::Registry::HKEY_LOCAL_MACHINE.open('SOFTWARE\Cygwin\setup\rootdir') do |reg|
  #      reg_typ, reg_val = reg.read('')
  #      return reg_val
  #  end
	#end
  
  def checkexe(command)
  end

  def validatecmd(command)
    true
  end

  private
  def write_script(content, &block)
    Tempfile.open(['puppet-cygwin_exec', '.sh']) do |file|
      file.write(content)
      file.flush
      yield native_path(file.path)
    end
  end

  def native_path(path)
    #@log.info("native_path begin. path: #{path}")
    path.gsub(File::SEPARATOR, File::ALT_SEPARATOR)
  end

  def args
    '--login'
  end
end

