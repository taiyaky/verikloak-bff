# frozen_string_literal: true

RSpec.describe Verikloak::BFF::Rails::Middleware do
  before do
    # Stub the core middleware constant instead of defining it for real so the
    # global Verikloak namespace is restored after each example.
    stub_const('Verikloak::Middleware', Class.new)
  end

  let(:core_middleware) { Verikloak::Middleware }
  let(:stack) { double('MiddlewareStack') }

  describe '.insert_before_core' do
    it 'inserts the header guard before the core middleware when present' do
      allow(stack).to receive(:each).and_yield(double('Entry', klass: core_middleware))
      expect(stack).to receive(:insert_before).with(core_middleware, Verikloak::BFF::HeaderGuard)
      expect(described_class.insert_before_core(stack, logger: nil)).to be(true)
    end

    it 'detects the core middleware when it is referenced by string name' do
      allow(stack).to receive(:include?).and_return(false)
      allow(stack).to receive(:each).and_yield('Verikloak::Middleware')
      expect(stack).to receive(:insert_before).with(core_middleware, Verikloak::BFF::HeaderGuard)

      expect(described_class.insert_before_core(stack, logger: nil)).to be(true)
    end

    it 'detects the core middleware when wrapped in an array entry' do
      allow(stack).to receive(:include?).and_return(false)
      allow(stack).to receive(:each).and_yield([core_middleware, {}])
      expect(stack).to receive(:insert_before).with(core_middleware, Verikloak::BFF::HeaderGuard)

      expect(described_class.insert_before_core(stack, logger: nil)).to be(true)
    end

    it 'detects the core middleware when wrapped in a middleware entry with args' do
      middleware_entry = double('MiddlewareEntry', klass: core_middleware, args: [])
      allow(stack).to receive(:include?).and_return(false)
      allow(stack).to receive(:each).and_yield(middleware_entry)
      expect(stack).to receive(:insert_before).with(core_middleware, Verikloak::BFF::HeaderGuard)

      expect(described_class.insert_before_core(stack, logger: nil)).to be(true)
    end

    it 'detects the core middleware by name when stack contains complex objects' do
      complex_object = double('ComplexObject', name: 'Verikloak::Middleware')
      allow(stack).to receive(:include?).and_return(false)
      allow(stack).to receive(:each).and_yield(complex_object)
      expect(stack).to receive(:insert_before).with(core_middleware, Verikloak::BFF::HeaderGuard)

      expect(described_class.insert_before_core(stack, logger: nil)).to be(true)
    end

    it 'skips insertion with a warning when the core middleware is missing' do
      allow(stack).to receive(:each)
      logger = instance_double('Logger')
      expect(logger).to receive(:warn).with(a_string_matching('Skipping Verikloak::BFF::HeaderGuard insertion'))
      expect(stack).not_to receive(:insert_before)

      expect(described_class.insert_before_core(stack, logger: logger)).to be(false)
    end

    it 'logs and skips when insertion fails because the core middleware is missing' do
      allow(stack).to receive(:each).and_yield(double('Entry', klass: core_middleware))
      error = RuntimeError.new('No such middleware to insert before: Verikloak::Middleware')
      allow(stack).to receive(:insert_before).and_raise(error)
      logger = instance_double('Logger')
      expect(logger).to receive(:warn).with(a_string_matching('Skipping Verikloak::BFF::HeaderGuard insertion'))

      expect(described_class.insert_before_core(stack, logger: logger)).to be(false)
    end

    it 're-raises unexpected runtime errors' do
      allow(stack).to receive(:each).and_yield(double('Entry', klass: core_middleware))
      allow(stack).to receive(:insert_before).and_raise(RuntimeError, 'boom')

      expect {
        described_class.insert_before_core(stack, logger: nil)
      }.to raise_error(RuntimeError, 'boom')
    end

    it 'gracefully handles when verikloak gem is not loaded' do
      hide_const('Verikloak::Middleware')

      expect(stack).not_to receive(:insert_before)
      logger = instance_double('Logger')
      expect(logger).to receive(:warn).with(a_string_matching('Skipping Verikloak::BFF::HeaderGuard insertion'))

      expect(described_class.insert_before_core(stack, logger: logger)).to be(false)
    end
  end

  describe '.insert_after_core (deprecated)' do
    it 'warns about deprecation and delegates to insert_before_core' do
      allow(stack).to receive(:each).and_yield(double('Entry', klass: core_middleware))
      logger = instance_double('Logger')
      expect(logger).to receive(:warn).with(a_string_matching('insert_after_core is deprecated'))
      expect(stack).to receive(:insert_before).with(core_middleware, Verikloak::BFF::HeaderGuard)

      expect(described_class.insert_after_core(stack, logger: logger)).to be(true)
    end

    it 'emits the deprecation warning to stderr when no logger is given' do
      allow(stack).to receive(:each).and_yield(double('Entry', klass: core_middleware))
      allow(stack).to receive(:insert_before)

      expect {
        described_class.insert_after_core(stack, logger: nil)
      }.to output(/insert_after_core is deprecated/).to_stderr
    end
  end
end
