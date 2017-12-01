from setuptools import setup


setup(
    name='Flask-Auth0',
    version='2019.04.01',
    url='http://github.com/djoek/flask-auth0/',
    license='BSD',
    author='djoek',
    author_email='flask-auth0@djoek.net',
    description='An Auth0 Authorization Code flow extension for flask',
    long_description=__doc__,
    packages=['flask_auth0'],
    zip_safe=False,
    include_package_data=True,
    platforms='any',
    install_requires=[
        'Flask', 'requests', 'python-jose[pycryptodome]',
    ],
    classifiers=[
        'Environment :: Web Environment',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: BSD License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Topic :: Internet :: WWW/HTTP :: Dynamic Content',
        'Topic :: Software Development :: Libraries :: Python Modules'
    ]
)
