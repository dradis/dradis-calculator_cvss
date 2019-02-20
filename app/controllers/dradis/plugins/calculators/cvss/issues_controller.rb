module Dradis::Plugins::Calculators::CVSS
  # Does it matter that we're inheriting from the no-frills controller?
  class IssuesController < ::IssuesController
    before_action :set_cvss_vector, only: :edit

    def edit
    end

    def update
      cvss_fields = Hash[ *params[:cvss_fields].scan(HasFields::REGEX).flatten.map(&:strip) ]
      cvss_fields.each do |name, value|
        @issue.set_field(name, value)
      end

      if @issue.save
        redirect_to main_app.project_issue_path(current_project, @issue), notice: 'CVSSv3 fields updated.'
      else
        render :edit
      end
    end

    def set_cvss_vector
      # Undefined Temporal and Environmental default to X
      @cvss_vector = Hash.new { |h, k| h[k] = 'X' }
      field_value  = @issue.fields['CVSSv3.Vector'] || @issue.fields['CVSSv3Vector']
      if field_value
        field_value.split('/').each { |pair| @cvss_vector.store *pair.split(':') }
      end
    end
  end
end
