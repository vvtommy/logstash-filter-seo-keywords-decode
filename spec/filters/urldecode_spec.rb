# encoding: utf-8

require "logstash/devutils/rspec/spec_helper"
require "logstash/filters/seodecode"

describe LogStash::Filters::Seodecode do
  describe "urldecode of correct urlencoded data" do
    # The logstash config goes here.
    # At this time, only filters are supported.
    config <<-CONFIG
      filter {
        seodecode {
        }
      }
    CONFIG

    sample("message" => "http%3A%2F%2Flogstash.net%2Fdocs%2F1.3.2%2Ffilters%2Furldecode") do
      insist { subject["message"] } == "http://logstash.net/docs/1.3.2/filters/urldecode"
    end
  end

  describe "urldecode of incorrect urlencoded data" do
    config <<-CONFIG
      filter {
        seodecode {
        }
      }
    CONFIG

    sample("message" => "http://logstash.net/docs/1.3.2/filters/urldecode") do
      insist { subject["message"] } == "http://logstash.net/docs/1.3.2/filters/urldecode"
    end
  end

   describe "urldecode with all_fields set to true" do
    # The logstash config goes here.
    # At this time, only filters are supported.
    config <<-CONFIG
      filter {
        seodecode {
          all_fields => true
        }
      }
    CONFIG

    sample("message" => "http%3A%2F%2Flogstash.net%2Fdocs%2F1.3.2%2Ffilters%2Furldecode", "nonencoded" => "http://logstash.net/docs/1.3.2/filters/urldecode") do
      insist { subject["message"] } == "http://logstash.net/docs/1.3.2/filters/urldecode"
      insist { subject["nonencoded"] } == "http://logstash.net/docs/1.3.2/filters/urldecode"
    end
  end

   describe "urldecode should replace invalid UTF-8" do
     config <<-CONFIG
      filter {
        seodecode {}
      }
     CONFIG
     sample("message" => "/a/sa/search?rgu=0;+%C3%BB%D3%D0%D5%D2%B5%BD=;+%B7%A2%CB%CD=") do
      insist { subject["message"] } == "/a/sa/search?rgu=0;+û\\xD3\\xD0\\xD5ҵ\\xBD=;+\\xB7\\xA2\\xCB\\xCD="
     end
   end
end
