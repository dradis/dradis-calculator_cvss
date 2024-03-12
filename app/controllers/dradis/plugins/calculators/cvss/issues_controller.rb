module Dradis::Plugins::Calculators::CVSS
  # Does it matter that we're inheriting from the no-frills controller?
  class IssuesController < ::IssuesController
    before_action :set_cvss_vector, only: :edit

    def edit
      @cvss_version =
        if @issue.fields['CVSSv4.BaseVector']
          '4.0'
        elsif @issue.fields['CVSSv3.Vector']&.include?('CVSS:3.1')
          '3.1'
        elsif @issue.fields['CVSSv3.Vector']&.include?('CVSS:3.0')
          '3.0'
        else
          '4.0'
        end
    end

    def update
      cvss_fields = Hash[ *params[:cvss_fields].scan(FieldParser::FIELDS_REGEX).flatten.map(&:strip) ]
      cvss_fields.each do |name, value|
        @issue.set_field(name, value)
      end

      if @issue.save
        redirect_to main_app.project_issue_path(current_project, @issue), notice: 'CVSS fields updated.'
      else
        render :edit
      end
    end

    def set_cvss_vector
      # Undefined Temporal and Environmental default to X
      @cvss_vector = Hash.new { |h, k| h[k] = 'X' }
      @cvss4_vector = Dradis::Plugins::Calculators::CVSS::V4::DEFAULT_CVSS_V4.clone
      field_value_v3 = @issue.fields['CVSSv3.Vector'] || @issue.fields['CVSSv3Vector']
      field_value_v4  = @issue.fields['CVSSv4.BaseVector']

      # If no vector is set yet, that's OK
      return if field_value_v3.blank? && field_value_v4.blank?

      if field_value_v3
        if field_value_v3 =~ V3::VECTOR_REGEXP
          field_value_v3.split('/').each { |pair| @cvss_vector.store *pair.split(':') }
        else
          redirect_to main_app.project_issue_path(current_project, @issue), alert: 'The format of the CVSSv3 Vector field is invalid.'
        end
      end

      if field_value_v4
        if field_value_v4.starts_with?('CVSS:4.0')
          field_value_v4.split('/').each { |pair| @cvss4_vector.store *pair.split(':') }
        else
          redirect_to main_app.project_issue_path(current_project, @issue), alert: 'The format of the CVSSv4 Vector field is invalid.'
        end
      end
    end
  end
end
